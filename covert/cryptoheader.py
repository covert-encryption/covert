import random
from contextlib import suppress

from nacl.exceptions import CryptoError

from covert import chacha, passphrase, pubkey, util


def encrypt_header(auth):
  wideopen, pwhashes, recipients, identities = auth
  assert wideopen or pwhashes or recipients, "Must have an authentication method defined"
  assert not wideopen or not (pwhashes or recipients), "Cannot have auth with wide-open"
  # Ensure uniqueness
  pwhashes = set(pwhashes)
  recipients = set(recipients)
  simple = not recipients and len(pwhashes) <= 1
  # Create a random ephemeral keypair and use it as nonce (even when no pubkeys are used)
  eph = pubkey.Key()
  n = eph.pkhash[:12]
  nonce = util.noncegen(n)
  # Only one password or wide-open
  if simple:
    key = bytes(32) if wideopen else passphrase.authkey(pwhashes.pop(), n)
    return n, nonce, key
  # Pubkeys and/or multiple auth mode
  auth = {passphrase.authkey(pw, n) for pw in pwhashes} | {pubkey.derive_symkey(n, eph, r) for r in recipients}
  if len(auth) > 20:
    raise ValueError("Too many recipients specified (max 20).")
  auth = list(auth)
  random.shuffle(auth)
  # The first hash becomes the key and any additional ones are xorred with it
  key, *auth = auth
  header = eph.pkhash + b"".join([util.xor(key, a) for a in auth])
  return header, nonce, key


class Header:
  def __init__(self, ciphertext):
    if len(ciphertext) < 32:  # 12 nonce + 1 data + 3 nextlen + 16 tag
      raise ValueError("This file is too small to contain encrypted data.")
    self.ciphertext = bytes(ciphertext[:1024])
    self.nonce = self.ciphertext[:12]
    self.eph = pubkey.Key(pkhash=self.ciphertext[:32])
    self.slot = "locked"
    self.key = None
    self.block0pos = None
    self.block0len = None
    with suppress(CryptoError):
      # Try wide-open
      self._find_block0(bytes(32), 12)
      self.slot = "wide-open"

  def try_key(self, recvkey):
    self._find_slots(pubkey.derive_symkey(self.nonce, recvkey, self.eph))

  def try_pass(self, pwhash):
    authkey = passphrase.authkey(pwhash, self.nonce)
    try:
      self._find_block0(authkey, 12)
      self.slot = "passphrase"
    except CryptoError:
      self._find_slots(authkey)

  def _find_slots(self, authkey):
    # The first slot is all zeroes (not stored in file), followed by auth1, auth2, ...
    ct = self.ciphertext
    slots = [bytes(32)] + [ct[i * 32:(i+1) * 32] for i in range(1, 19) if (i+1) * 32 <= len(ct) - 19]
    slotends = [(i+1) * 32 for i in range(len(slots))]
    for i, s in enumerate(slots):
      key = util.xor(s, authkey)
      for hbegin in slotends[i:]:
        with suppress(CryptoError):
          self._find_block0(key, hbegin)
          self.slot = i, self.block0pos // 32
          return
    raise CryptoError

  def _find_block0(self, key, begin):
    ct = self.ciphertext
    for end in reversed(range(begin + 19, 1 + min(1024, len(ct)))):
      with suppress(CryptoError):
        self.block0 = chacha.decrypt(ct[begin:end], ct[:begin], self.nonce, key)
        break
    else:
      raise CryptoError
    self.key = key
    self.block0pos = begin
    self.block0len = end - begin - 19
