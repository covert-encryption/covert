from __future__ import annotations
from typing import List

# Unfortunately pynacl does not offer AES at all.
# It would be nice if this could be replaced with some tiny AES library.
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import CTR

from base64 import b64decode
from covert import passphrase, pubkey, util
import bcrypt

HEADER = "-----BEGIN OPENSSH PRIVATE KEY-----"
FOOTER = "-----END OPENSSH PRIVATE KEY-----"


def decode_armor(data: str) -> bytes:
  pos1 = data.find(HEADER)
  pos2 = data.find(FOOTER, pos1)
  if pos2 == -1:
    raise ValueError("Not SSH secret key (header or footer missing)")
  return b64decode(data[pos1 + len(HEADER) : pos2])


def decode_sk(pem: str, pw=None) -> List[pubkey.Key]:
  """Parse PEM or the Base64 binary data within a secret key file."""
  # None means try without password, then ask
  data = decode_armor(pem)

  def decrypt(message, nonce, key):
    c = Cipher(AES(key), CTR(nonce)).decryptor()
    return c.update(message) + c.finalize()

  def read_string():
    return read_bytes(read_uint32())

  def read_uint32():
    nonlocal data
    if len(data) < 4:
      raise ValueError("Invalid SSH secret key (cannot read int)")
    n = int.from_bytes(data[:4], "big")
    data = data[4:]
    return n

  def read_bytes(n):
    nonlocal data
    if n > len(data):
      raise ValueError(f" {data[:4]} {n} Invalid SSH secret key (cannot read data)")
    s = data[:n]
    data = data[n:]
    return s

  # Overall format (header + potentially encrypted blob)
  magic = read_bytes(15)
  if magic != b'openssh-key-v1\0':
    raise ValueError("Invalid SSH secret key magic")
  cipher = read_string()
  kdfname = read_string()
  kdfopts = read_string()
  numkeys = read_uint32()
  pubkeys = [read_string() for i in range(numkeys)]
  encrypted = read_string()

  # Quick exit if there is nothing we can use
  if not any(b"ssh-ed25519" in pk for pk in pubkeys):
    raise ValueError("No ssh-ed25519 keys found")

  # Decrypt if protected
  if cipher == b"none":
    data = encrypted
  elif cipher == b"aes256-ctr" and kdfname == b"bcrypt":
    data = kdfopts
    salt = read_string()
    rounds = read_uint32()
    # 16 is a normal value
    if rounds > 1000:
      raise ValueError("SSH secret key KDF rounds too high")
    if pw is None:
      pw = passphrase.ask("SSH secret key password")[0]
    if not pw:
      raise ValueError("Password required for SSH keyfile")
    keyiv = bcrypt.kdf(pw, salt, 32 + 16, rounds, ignore_few_rounds=True)
    data = decrypt(encrypted, keyiv[32:], keyiv[:32])
  else:
    raise ValueError("Unsupported SSH keyfile {cipher=!r} {kdfname=!r}")

  # Check if valid
  if read_uint32() != read_uint32():
    raise ValueError("Unable to decrypt SSH keyfile")

  # Read secret keys
  secretkeys = []
  for i, pkstr in enumerate(pubkeys):
    t = read_string().decode()
    if t == "ssh-ed25519":
      edpk, edsk, comment = read_string(), read_string(), read_string()
      secretkeys.append(pubkey.Key(edpk=edpk, edsk=edsk, comment=comment.decode()))
    elif t == "ecdsa-sha2-nistp256":
      *params, comment = [read_string() for _ in range(4)]
    elif t == "ssh-rsa":
      md, pe, se, coeff, p, q, comment = [read_string() for _ in range(7)]
    elif t == "ssh-dss":
      *params, comment = [read_string() for _ in range(6)]
    else:
      raise ValueError(f"Unknown SSH key type {t}")

  return secretkeys


# Implementation note: Apparently OpenSSH never puts more than one key in a file,
# but the above function follows the spec, allowing for any number of keys.
