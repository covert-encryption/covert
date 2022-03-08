import mmap
import os
import time
from contextlib import suppress
from copy import copy
from pathlib import Path

from covert import passphrase, pubkey, ratchet
from covert.archive import Archive
from covert.blockstream import decrypt_file, encrypt_file
from covert.path import create_datadir, idfilename


def create(pwhash, idstore=None):
  a = Archive()
  a.index["I"] = idstore or {}
  # Encrypt in RAM...
  out = b"".join(b for b in encrypt_file((False, [pwhash], [], []), a.encode, a))
  create_datadir()
  # Write the ID file
  with open(idfilename, "xb") as f:
    f.write(out)


def delete_entire_idstore():
  """Securely erase the entire idstore. Config folder is removed if empty."""
  with open(idfilename, "r+b") as f, mmap.mmap(f.fileno(), 0) as m:
    m[:] = bytes(len(m))
    os.fsync(f.fileno())
  idfilename.unlink()
  with suppress(OSError):
    idfilename.parent.rmdir()


def update(pwhash, allow_create=True, new_pwhash=None):
  if not new_pwhash:
    new_pwhash = pwhash
  if allow_create and not idfilename.exists():
    idstore = {}
    yield idstore
    if idstore: create(new_pwhash, idstore)
    return
  with open(idfilename, "r+b") as f, mmap.mmap(f.fileno(), 0) as m:
    # Decrypt everything to RAM
    a = Archive()
    for data in a.decode(decrypt_file([pwhash], m, a)):
      if isinstance(data, dict):
        if not "I" in data: data["I"] = dict()
      elif isinstance(data, bool):
        if data: a.curfile.data = bytearray()
      else: a.curfile.data += data
    # Yield the ID store for operations but do an update even on break/return etc
    with suppress(GeneratorExit):
      yield a.index["I"]
    # Remove expired records
    remove_expired(a.index["I"])
    # Reset archive for re-use in encryption
    a.reset()
    a.fds = [BytesIO(f.data) for f in a.flist]
    a.random_padding(p=0.2)
    # Encrypt in RAM...
    out = b"".join(b for b in encrypt_file((False, [new_pwhash], [], []), a.encode, a))
    # Overwrite the ID file
    if len(m) < len(out): m.resize(len(out))
    m[:len(out)] = out
    if len(m) > 2 * len(out): m.resize(len(m))

def profile(pwhash, idstr, idkey=None, peerkey=None):
  """Create/update ID profile"""
  parts = idstr.split(":", 1)
  local = parts[0]
  peer = parts[1] if len(parts) == 2 else ""
  tagself = f"id:{local}"
  for idstore in update(pwhash):
    # If no peer given, create a pseudonymous peername
    while not peer:
      peer = f".{passphrase.generate(2)}"
      if f"id:{local}:{peer}" in idstore: peer = None
    tagpeer = f"id:{local}:{peer}"
    # Allow using local IDs as peers
    taglocalpeer = f"id:{peer}"
    if local == peer or taglocalpeer in idstore:
      if peerkey: raise ValueError(f"ID {peer} already in store as a local user, cannot have a recipient key specified.")
    else:
      taglocalpeer = None
    if not (taglocalpeer or peerkey or tagpeer in idstore):
      raise ValueError("Peer not in ID store. You need to specify a recipient public key on the first use.")
    # Load/generate keys if needed
    if not idkey:
      idkey = pubkey.Key(sk=idstore[tagself]["I"]) if tagself in idstore else pubkey.Key()
    if taglocalpeer:
      peerkey = idkey if local == peer else pubkey.Key(sk=idstore[taglocalpeer]["I"])
    elif not peerkey:
      peerkey = pubkey.Key(pk=idstore[tagpeer]["i"])
    # Add/update records
    if tagself not in idstore: idstore[tagself] = dict()
    if tagpeer not in idstore: idstore[tagpeer] = dict()
    idstore[tagself]["I"] = idkey.sk
    idstore[tagpeer]["i"] = peerkey.pk
    idkey = copy(idkey)
    peerkey = copy(peerkey)
    idkey.comment = tagself
    peerkey.comment = tagpeer
    r = ratchet.Ratchet()
    if "r" in idstore[tagpeer]:
      r.load(idstore[tagpeer]["r"])
    else:
      idstore[tagpeer]["r"] = r.store()
    # These values are not stored in id store but are kept runtime
    r.tagpeer = tagpeer
    r.idkey = idkey
    r.peerkey = peerkey
  return idkey, peerkey, r


def update_ratchet(pwhash, ratch, a):
  if 'r' in a.index:
    ratch.prepare_alice(a.filehash[:32], ratch.idkey)
  for idstore in update(pwhash):
    idstore[ratch.tagpeer]["r"] = ratch.store()

def save_contact(pwhash, idname, a, b):
  localkey = b.header.authkey
  peerkey = a.signatures[0][1]
  for idstore in update(pwhash):
    idstore[f"id:{idname}"] = {}
    idstore[f"id:{idname}"]["i"] = peerkey.pk
    if "r" in a.index:
      r = ratchet.Ratchet()
      r.init_bob(a.filehash[:32], localkey, peerkey)
      idstore[f"id:{idname}"]["r"] = r.store()

def authgen(pwhash):
  """Try all authentication keys from the keystore"""
  for idstore in update(pwhash, allow_create=False):
    try:
      for key, value in idstore.items():
        if "r" in value:
          r = ratchet.Ratchet()
          r.load(value['r'])
          r.idkey = key
          r.peerkey = pubkey.Key(pk=value['i'])
          try:
            yield r
          except GeneratorExit:
            # If the ratchet was used, store back with changes
            value['r'] = r.store()
            raise
        if "I" in value: yield pubkey.Key(comment=key, sk=value["I"])
    except GeneratorExit:
      break

def idkeys(pwhash):
  keys = {}
  for idstore in update(pwhash, allow_create=False):
    for key, value in idstore.items():
      if "I" in value:
        k = pubkey.Key(comment=key, sk=value["I"])
        keys[k] = k
      elif "i" in value:
        k = pubkey.Key(comment=key, pk=value["i"])
        if k not in keys: keys[k] = k
  return keys


def remove_expired(ids: dict) -> None:
  """Delete all records that have expired."""
  t = time.time()
  for k in list(ids):
    v = ids[k]
    # The entire peer
    if "e" in v and v["e"] < t:
      del ids[k]
      continue
    if "r" in v:
      r = v["r"]
      # The entire ratchet
      if r["e"] < t:
        del v["r"]
        continue
      # Message keys
      r["msg"] = [m for m in r['msg'] if m["e"] > t]
