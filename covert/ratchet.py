import itertools
from contextlib import suppress
import time

import nacl.bindings as sodium
from nacl.exceptions import CryptoError

from covert.chacha import decrypt, encrypt
from covert.pubkey import Key, derive_symkey

MAXSKIP = 20

def expire_soon():
  return int(time.time()) + 600  # 10 minutes

def expire_later():
  return int(time.time()) + 86400 * 28  # four weeks

def chainstep(chainkey: bytes, addn=b""):
  """Perform a chaining step, returns (new chainkey, message key)."""
  h = sodium.crypto_hash_sha512(chainkey + addn)
  return h[:32], h[32:]


class SymChain:
  def __init__(self):
    self.CK = None
    self.HK = None
    self.NHK = None
    self.CN = 0
    self.PN = 0
    self.N = 0

  def store(self):
    return dict(
      CK=self.CK,
      HK=self.HK,
      NHK=self.NHK,
      CN=self.CN,
      PN=self.PN,
      N=self.N,
    )

  def load(self, chain):
    self.CK = chain['CK']
    self.HK = chain['HK']
    self.NHK = chain['NHK']
    self.CN = chain['CN']
    self.PN = chain['PN']
    self.N = chain['N']

  def dhstep(self, ratchet, peerkey):
    shared = derive_symkey(b"ratchet", ratchet.DH, peerkey)
    self.CN += self.N
    self.PN = self.N
    self.N = 0
    self.HK = self.NHK
    ratchet.RK, self.CK = chainstep(ratchet.RK, shared)
    _, self.NHK = chainstep(ratchet.RK, b"hkey")

  def __next__(self):
    self.CK, MK = chainstep(self.CK)
    self.N += 1
    return MK

class Ratchet:
  def __init__(self):
    self.RK = None
    self.DH = None
    self.s = SymChain()
    self.r = SymChain()
    self.msg = []
    self.pre = []
    self.e = expire_later()
    # Runtime values, not saved
    self.peerkey = None
    self.idkey = None

  def store(self):
    return dict(
      RK=self.RK,
      DH=self.DH.sk if self.DH else None,
      s=self.s.store(),
      r=self.r.store(),
      msg=self.msg,
      pre=self.pre,
      e=self.e,
    )

  def load(self, ratchet):
    self.RK = ratchet['RK']
    self.DH = Key(sk=ratchet['DH']) if ratchet['DH'] else None
    self.s.load(ratchet['s'])
    self.r.load(ratchet['r'])
    self.msg = ratchet['msg']
    self.pre = ratchet['pre']
    self.e = ratchet['e']

  def prepare_alice(self, shared, localkey):
    """Alice sends non-ratchet initial message."""
    self.pre.append(shared)
    self.pre = self.pre[-MAXSKIP:]
    self.DH = localkey
    self.s.N += 1
    self.e = expire_later()

  def init_bob(self, shared, localkey, peerkey):
    """Bob receives an initial message from Alice, initialise ratchet on Bob side for replies."""
    self.DH = localkey
    self.RK = shared
    self.s.NHK = shared
    self.dhratchet(peerkey)
    self.e = expire_later()

  def init_alice(self, ciphertext):
    """Alice's init when receiving initial ratchet reply from Bob."""
    for hkey, n in itertools.product(self.pre, range(MAXSKIP)):
      with suppress(CryptoError):
        header = decrypt(ciphertext[:50], None, n.to_bytes(12, "little"), hkey)
        break
    else:
      raise CryptoError("No ratchet established, unable to decrypt")
    self.pre = []
    self.RK = hkey
    self.r.NHK = hkey
    self.s.dhstep(self, self.peerkey)
    self.dhratchet(Key(pk=header[:32]))
    self.skip_until(n)
    self.e = expire_later()
    return self.readmsg()

  def send(self, peerkey=None):
    header = encrypt(self.DH.pk + self.s.PN.to_bytes(2, "little"), None, self.s.N.to_bytes(12, "little"), self.s.HK)
    self.e = expire_later()
    return header, next(self.s)

  def receive(self, ciphertext):
    if self.pre:
      return self.init_alice(ciphertext)
    # Try skipped keys
    for s in self.msg:
      hkey, n = s['H'], s['N']
      with suppress(CryptoError):
        header = decrypt(ciphertext[:50], None, n.to_bytes(12, "little"), hkey)
        s['e'] = expire_soon()
        s['r'] = True
        mk = s['M']
        self.e = expire_later()
        return mk
    header = None
    # Try with current header key
    if self.r.HK:
      for n in range(self.r.N, self.r.N + MAXSKIP):
        with suppress(CryptoError):
          header = decrypt(ciphertext[:50], None, n.to_bytes(12, "little"), self.r.HK)
          self.skip_until(n)
          break
    # Try with next header key
    if not header:
      for n in range(MAXSKIP):
        with suppress(CryptoError):
          header = decrypt(ciphertext[:50], None, n.to_bytes(12, "little"), self.r.NHK)
          PN = int.from_bytes(header[32:34], "little")
          self.skip_until(PN)
          self.dhratchet(Key(pk=header[:32]))
          self.skip_until(n)
    if not header:
      raise CryptoError(f"Unable to authenticate")
    self.e = expire_later()
    # Advance receiving chain
    return self.readmsg()

  def dhratchet(self, peerkey):
    """Perform two DH steps to update all chains."""
    self.r.dhstep(self, peerkey)
    self.DH = Key()
    self.s.dhstep(self, peerkey)

  def skip_until(self, n):
    """Advance the receiving chain across all messages prior to message n."""
    while self.r.N < n:
      self.msg.append(dict(
        H=self.r.HK,
        N=self.r.N,
        M=next(self.r),
        e=expire_soon(),
      ))

  def readmsg(self):
    m = dict(
      H=self.r.HK,
      N=self.r.N,
      M=next(self.r),
      e=expire_soon(),
      r=True,
    )
    self.msg.append(m)
    self.msg = self.msg[-MAXSKIP:]
    return m['M']


# Alice sends non-ratchet, includes pk, stores shared secret

# Bob decrypts, calls init_bob, sends ratchet reply nhks=shared
#  - init RK, recv chain(ii, nhk), new key, send chain(xi)

# Alice receives ratchet reply, shared secret as nhk
#  - init RK, send chain(ii, nhk),          recv chain(ix), new key, send chain(xx)

# Bob receives reply
#                                                                  - recv chain(xx), new key, send chain(xx)
