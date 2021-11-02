import random
from contextlib import suppress

from nacl.exceptions import CryptoError

from covert import chacha, passphrase, pubkey, util


def encrypt_header(auth):
  noauth, authpw, authpk, identities = auth
  assert noauth or authpw or authpk, "Must have an authentication method defined"
  assert not noauth or (not authpw and not authpk), "Cannot have auth with noauth"
  simple = not authpk and len(authpw) <= 1
  eph_pk, eph_sk = pubkey.create_ephkeys()
  n = eph_pk[:12]
  nonce = util.noncegen(n)
  # Only one password or wide-open
  if simple:
    key = passphrase.argon2(authpw[0], n) if authpw else bytes(32)
    return n, nonce, key
  # Pubkeys and/or multiple auth mode
  auth = [passphrase.argon2(pw, n) for pw in set(authpw)]
  auth += [pubkey.derive_recipient(eph_sk, peerpk, n) for peerpk in authpk]
  random.shuffle(auth)
  # The first hash becomes the key and any additional ones are xorred with it
  key, *auth = auth
  header = eph_pk + b"".join([util.xor(key, a) for a in auth])
  return header, nonce, key


def decrypt_header(ciphertext, auth):
  authpw, authpk, identity = auth
  if len(ciphertext) < 31:  # 12 nonce + 0 data + 3 nextlen + 16 tag
    raise ValueError("This file is too small to contain encrypted data.")
  eph_pk = ciphertext[:32]
  nonce = util.noncegen(ciphertext[:12])
  n = next(nonce)
  # Try wide-open
  key = bytes(32)
  with suppress(CryptoError):
    return *find_header_hend(ciphertext, n, key, 12), nonce
  # Try public keys
  for a in identity:
    recv_sk = pubkey.decode_sk(a)
    key = pubkey.derive_symkey(n, recv_sk, eph_pk)
    with suppress(CryptoError):
      return *find_header_slots(ciphertext, n, key), nonce
  # Try passwords
  for a in authpw:
    if a is True:
      a = passphrase.ask(f"Passphrase")[0]
    key = passphrase.argon2(a, n)
    # Single password
    with suppress(CryptoError):
      return *find_header_hend(ciphertext, n, key, 12), nonce
    # Multiple auth
    with suppress(CryptoError):
      return *find_header_slots(ciphertext, n, key), nonce
  raise ValueError("Unable to decrypt.")


def find_header_slots(ct, n, key):
  slots = [bytes(32)] + [ct[i * 32: (i+1) * 32] for i in range(1, 19) if (i+1) * 32 <= len(ct) - 19]
  slotends = [(i+1) * 32 for i in range(len(slots))]
  for i, s in enumerate(slots):
    k = util.xor(s, key)
    for hbegin in slotends[i:]:
      with suppress(CryptoError):
        return find_header_hend(ct, n, k, hbegin)
  raise CryptoError


def find_header_hend(ct, n, key, hbegin):
  for hend in reversed(range(hbegin + 19, 1 + min(1024, len(ct)))):
    with suppress(CryptoError):
      data = chacha.decrypt(bytes(ct[hbegin:hend]), bytes(ct[:hbegin]), n, key)
      return data, hend, key
  raise CryptoError
