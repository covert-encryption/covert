import random
from contextlib import suppress

from nacl.exceptions import CryptoError

from covert import chacha, passphrase, pubkey, util


def encrypt_header(auth):
  wideopen, passwords, recipients, identities = auth
  assert wideopen or passwords or recipients, "Must have an authentication method defined"
  assert not wideopen or not (passwords or recipients), "Cannot have auth with wide-open"
  simple = not recipients and len(passwords) <= 1
  # Create a random ephemeral keypair and use it as nonce (even when no pubkeys are used)
  eph = pubkey.Key()
  n = eph.pk[:12]
  nonce = util.noncegen(n)
  # Only one password or wide-open
  if simple:
    key = bytes(32) if wideopen else passphrase.argon2(passwords[0], n)
    return n, nonce, key
  # Pubkeys and/or multiple auth mode
  auth = [passphrase.argon2(pw, n) for pw in set(passwords)]
  auth += [pubkey.derive_symkey(n, eph, r) for r in set(recipients)]
  # It is crucial to remove any duplicates
  auth = list(set(auth))
  random.shuffle(auth)
  # The first hash becomes the key and any additional ones are xorred with it
  key, *auth = auth
  header = eph.pk + b"".join([util.xor(key, a) for a in auth])
  return header, nonce, key


def decrypt_header(ciphertext, auth):
  passwords, identities = auth
  if len(ciphertext) < 32:  # 12 nonce + 1 data + 3 nextlen + 16 tag
    raise ValueError("This file is too small to contain encrypted data.")
  nonce = util.noncegen(ciphertext[:12])
  n = next(nonce)
  # Try wide-open
  key = bytes(32)
  with suppress(CryptoError):
    return *find_header_hend(ciphertext, n, key, 12), nonce
  # Try public keys
  eph = pubkey.Key(pk=ciphertext[:32])
  for idkey in identities:
    key = pubkey.derive_symkey(n, idkey, eph)
    with suppress(CryptoError):
      return *find_header_slots(ciphertext, n, key), nonce
  # Ask for passphrase if no auth was supplied
  if not passwords and not identities:
    passwords = [passphrase.ask('Passphrase')[0]]
  # Try passwords
  for a in passwords:
    key = passphrase.argon2(a, n)
    # Single password
    with suppress(CryptoError):
      return *find_header_hend(ciphertext, n, key, 12), nonce
    # Multiple auth
    with suppress(CryptoError):
      return *find_header_slots(ciphertext, n, key), nonce
  raise ValueError("Unable to decrypt.")


def find_header_slots(ct, n, key):
  slots = [bytes(32)] + [ct[i * 32:(i+1) * 32] for i in range(1, 19) if (i+1) * 32 <= len(ct) - 19]
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
