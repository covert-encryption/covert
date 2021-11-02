import os
from base64 import b64decode
from urllib.request import urlopen

import nacl.bindings as sodium

from covert import bech


def decode_pk(keystr):
  SSH_ED25519 = "AAAAC3NzaC1lZDI1NTE5AAAA"
  if keystr.startswith("age1"):
    return decode_age_pk(keystr)
  if keystr.startswith("github:"):
    lines = [
      l for l in urlopen(f"https://github.com/{keystr[7:]}.keys").read().split(b"\n") if SSH_ED25519 in l.decode()
    ]
    if not lines:
      raise ValueError(f"No ed25519 keys found at {keystr}.")
    keystr = lines[0].decode()
  if SSH_ED25519 not in keystr and os.path.isfile(keystr):
    with open(keystr, "rb") as f:
      lines = [l for l in f.read().split(b"\n") if SSH_ED25519 in l.decode()]
      if not lines:
        raise ValueError(f"No ed25519 keys found in {keystr}.")
      keystr = lines[0].decode()
  if SSH_ED25519 in keystr:  # ssh-ed25519
    pos = keystr.find(SSH_ED25519)
    keystr = keystr[pos:pos + 68].split(" ")[0]
    edpk = b64decode(keystr)[-32:]
    return sodium.crypto_sign_ed25519_pk_to_curve25519(edpk)
  raise ValueError(f"Unrecognized key {keystr}")


def decode_sk(keystr):
  if isinstance(keystr, bytes):
    return keystr
  if keystr.lower().startswith("age-secret-key-"):
    return decode_age_sk(keystr)
  with open(keystr, "rb") as f:
    data = f.read()
    # This needs cleanup, perhaps also a real parser instead of this hack,
    # and support for encrypted keyfiles
    if data.startswith(b"-----BEGIN OPENSSH PRIVATE KEY-----"):
      data = b64decode(b"".join(data.split(b"\n")[1:-1]))
      magic = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00 "
      while magic in data:
        pos = data.find(magic) + len(magic)
        pk = data[pos:pos + 32]
        pos2 = data.find(pk + b"\x00\x00\x00@")
        pk2 = data[pos2:pos2 + 32]
        if pk2 == pk:
          sk = data[pos2 + 36:pos2 + 36 + 64]
        key = sodium.crypto_sign_ed25519_sk_to_curve25519(sk)
        if sodium.crypto_sign_ed25519_pk_to_curve25519(pk) == sodium.crypto_scalarmult_base(key):
          #cmtlen = int.from_bytes(data[pos2 + 36 + 64:pos2 + 36 + 64 + 4], "big")
          #cmt = data[pos2 + 36 + 64 + 4:pos2 + 36 + 64 + 4 + cmtlen].decode()
          #pkhash = b64encode(data[pos - len(magic):pos + 32]).decode()
          return key
        data = data[pos + len(magic):]
  raise ValueError(f"No private key found for identity {keystr}")


def sk_to_pk(privkey):
  return sodium.crypto_scalarmult_base(privkey)


def derive_symkey(nonce, sk, pk):
  assert len(sk) == 32, f"{len(sk)=}"
  assert len(pk) == 32, f"{len(pk)=}"
  shared = sodium.crypto_scalarmult(bytes(sk), bytes(pk))
  return sodium.crypto_hash_sha512(bytes(nonce) + shared)[:32]


def create_ephkeys():
  eph_pk, eph_sk = sodium.crypto_kx_keypair()
  return eph_pk, eph_sk


def derive_recipient(eph_sk, peer_pk, n):
  peer_pk = decode_pk(peer_pk)
  return derive_symkey(n, eph_sk, peer_pk)


def decode_age_pk(keystr):
  return bech.decode("age", keystr.lower())


def encode_age_pk(key):
  return bech.encode("age", key)


def decode_age_sk(keystr):
  return bech.decode("age-secret-key-", keystr.lower())


def encode_age_sk(key):
  return bech.encode("age-secret-key-", key).upper()
