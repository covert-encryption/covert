from covert import passphrase, pubkey
from covert.blockstream import encrypt_file, decrypt_file
from covert.archive import Archive
from pathlib import Path
import mmap
import subprocess
import os

def idfilename():
  # TODO: Use xdg paths such as ~/.config/covert/idstore on unix systems
  return Path.home() / ".covert" / "idstore"

def create(pwhash, idstore=None):
  a = Archive()
  a.index["I"] = idstore or {}
  # Encrypt in RAM...
  out = b"".join(b for b in encrypt_file((False, [pwhash], [], []), a.encode, a))
  fn = idfilename()
  confdir = idfilename().parent
  if not confdir.exists():
    confdir.mkdir(parents=True)
    if os.name == "posix":
      confdir.chmod(0o700)
      # Attempt to disable CoW (in particular with btrfs and zfs)
      ret = subprocess.run(["chattr", "+C", confdir], capture_output=True)
  # Write the ID file
  with open(fn, "xb") as f:
    if os.name == "posix": fn.chmod(0o600)
    f.write(out)

# pwhash = passphrase.pwhash(passphrase.ask("ID Master Passphrase")[0])

def update(pwhash, allow_create=True):
  fn = idfilename()
  if allow_create and not fn.exists():
    idstore = {}
    yield idstore
    if idstore: create(pwhash, idstore)
    return
  with open(fn, "r+b") as f, mmap.mmap(f.fileno(), 0) as m:
    # Decrypt everything to RAM
    a = Archive()
    for data in a.decode(decrypt_file([pwhash], m, a)):
      if isinstance(data, dict):
        if not "I" in data:
          data["I"] = []
      elif isinstance(data, bool):
        if data: a.curfile.data = bytearray()
      else: a.curfile.data += data
    try:
      yield a.index["I"]
    except StopIteration:
      pass
    # Reset archive for re-use in encryption
    a.reset()
    a.fds = [BytesIO(f.data) for f in a.flist]
    a.random_padding(p=0.2)
    # Encrypt in RAM...
    out = b"".join(b for b in encrypt_file((False, [pwhash], [], []), a.encode, a))
    # Overwrite the ID file
    if len(m) < len(out): m.resize(len(out))
    m[:len(out)] = out
    if len(m) > 2.0 * len(out): m.resize(len(m))

def profile(pwhash, idstr, idkey=None, peerkey=None):
  parts = idstr.split(":", 1)
  local = parts[0]
  peer = parts[1] if len(parts) == 2 else ""
  tagself = f"id:{local}"
  for idstore in update(pwhash):
    if not peer:
      while True:
        peer = f".{passphrase.generate(2)}"
        if f"id:{local}:{peer}" not in idstore:
          break
    tagpeer = f"id:{local}:{peer}"
    if tagself not in idstore:
      idstore[tagself] = dict(I=(idkey or pubkey.Key()).sk)
    if tagpeer not in idstore:
      idstore[tagpeer] = dict()
    if peerkey:
      idstore[tagpeer]["i"] = peerkey.pk
  return pubkey.Key(comment=local, sk=idstore[tagself]["I"]), pubkey.Key(comment=peer, pk=idstore[tagpeer]["i"])

# Example
I = {
  "id:alice": {
    "I": bytes(32),
  },
  "id:alice:bob": {
    "i": bytes(32),
  },
}
