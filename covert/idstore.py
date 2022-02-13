import mmap
import os
import subprocess
from contextlib import suppress
from pathlib import Path
from xdg import xdg_config_home

from covert import passphrase, pubkey
from covert.archive import Archive
from covert.blockstream import decrypt_file, encrypt_file


confdir = xdg_config_home() / "covert"
idfilename = confdir / "idstore"


def create(pwhash, idstore=None):
  a = Archive()
  a.index["I"] = idstore or {}
  # Encrypt in RAM...
  out = b"".join(b for b in encrypt_file((False, [pwhash], [], []), a.encode, a))
  if not confdir.exists():
    confdir.mkdir(parents=True)
    if os.name == "posix":
      confdir.chmod(0o700)
      # Attempt to disable CoW (in particular with btrfs and zfs)
      ret = subprocess.run(["chattr", "+C", confdir], capture_output=True)  # nosec
  # Write the ID file
  with open(idfilename, "xb") as f:
    if os.name == "posix": idfilename.chmod(0o600)
    f.write(out)


def update(pwhash, allow_create=True):
  if allow_create and not idfilename.exists():
    idstore = {}
    yield idstore
    if idstore: create(pwhash, idstore)
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
    # Reset archive for re-use in encryption
    a.reset()
    a.fds = [BytesIO(f.data) for f in a.flist]
    a.random_padding(p=0.2)
    # Encrypt in RAM...
    out = b"".join(b for b in encrypt_file((False, [pwhash], [], []), a.encode, a))
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
    if not (peerkey or tagpeer in idstore):
      raise ValueError("Peer not in ID store. You need to specify a recipient public key on the first use.")
    # Add/update records
    if tagself not in idstore: idstore[tagself] = dict(I=pubkey.Key().sk)
    if tagpeer not in idstore: idstore[tagpeer] = dict()
    if idkey: idstore[tagself]["I"] = idkey.sk
    if peerkey: idstore[tagpeer]["i"] = peerkey.pk
  return pubkey.Key(comment=local, sk=idstore[tagself]["I"]), pubkey.Key(comment=peer, pk=idstore[tagpeer]["i"])


def authgen(pwhash):
  """Try all authentication keys from the keystore"""
  for idstore in update(pwhash, allow_create=False):
    try:
      for key, value in idstore.items():
        if "I" in value: yield pubkey.Key(comment=key, sk=value["I"])
    except GeneratorExit:
      break

# Example
I = {
  "id:alice": {
    "I": bytes(32),
  },
  "id:alice:bob": {
    "i": bytes(32),
  },
}
