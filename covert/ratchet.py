import nacl.bindings as sodium
from nacl.exceptions import CryptoError
from covert.chacha import encrypt, decrypt
from covert.pubkey import derive_symkey, Key
from contextlib import suppress

def chainstep(chainkey: bytes, addn=b""):
  """Perform a chaining step, returns (new chainkey, message key)."""
  h = sodium.crypto_hash_sha512(chainkey + addn)
  return h[:32], h[32:]


class Ratchet:
  def __init__(self):
    self.root = None
    self.localkey = None
    self.chain_send = None
    self.chain_recv = None
    self.h_recv = self.h_send = None
    self.nh_recv = self.nh_send = None
    self.PN = self.Ns = self.Nr = 0
    self.skipped = []

  def init_alice(self, localkey, peerkey):
    """Prepare Alice for sending initial message(s) to Bob using his public key."""
    self.root = derive_symkey(b"ratchet/init", localkey, peerkey)
    _, self.nh_recv = chainstep(self.root, b"hkey")
    self.localkey = localkey
    self._tock(peerkey)

  def init_bob(self, localkey, ciphertext):
    """Bob receives an initial message from Alice, initialise ratchet on Bob side for replies."""
    ephkey = Key(pkhash=ciphertext[:32])
    key = derive_symkey(ephkey.pkhash[:12], localkey, ephkey)
    header = decrypt(ciphertext[32:83], None, b"ratchet/init", key)
    peerkey = Key(pk=header[:32])
    N = int.from_bytes(header[32:34], "little")
    self.root = derive_symkey(b"ratchet/init", localkey, peerkey)
    _, self.nh_send = chainstep(self.root, b"hkey")  # Matches Alice's initial nh_recv
    self.localkey = localkey
    self.skip_until(N)
    self.dhstep(peerkey)
    self.chain_recv, mk = chainstep(self.chain_recv)
    self.Nr += 1
    return mk

  def dhstep(self, peerkey):
    """ECDH ratchet step, when message with new header key is received."""
    self.PN = self.Ns
    self.Ns = self.Nr = 0
    self.h_recv = self.nh_recv
    self._tick(peerkey)
    # Right here we should be in sync with the peer.
    self.localkey = Key()
    self.h_send = self.nh_send
    self._tock(peerkey)

  def _tick(self, peerkey):
    """DH update receiving keys"""
    self.root, self.chain_recv = chainstep(self.root, derive_symkey(b"ratchet", self.localkey, peerkey))
    _, self.nh_recv = chainstep(self.root, b"hkey")

  def _tock(self, peerkey):
    """DH update sending keys"""
    self.root, self.chain_send = chainstep(self.root, derive_symkey(b"ratchet", self.localkey, peerkey))
    _, self.nh_send = chainstep(self.root, b"hkey")

  def send(self, peerkey=None):
    f = 1  # Flags: 1 means signature
    if not self.chain_recv:
      # Alice initial message format
      ephkey = Key()
      key = derive_symkey(ephkey.pkhash[:12], ephkey, peerkey)
      header = ephkey.pkhash + encrypt(self.localkey.pk + (self.Ns & 0xFFFF).to_bytes(2, "little") + f.to_bytes(1, "little"), None, b"ratchet/init", key)
    else:
      # Normal ratchet message
      header = encrypt(self.localkey.pk + self.PN.to_bytes(2, "little") + f.to_bytes(1, "little"), None, self.Ns.to_bytes(12, "little"), self.h_send)
    self.chain_send, mk = chainstep(self.chain_send)
    self.Ns += 1
    return header, mk

  def receive(self, ciphertext):
    # Try skipped keys
    for [hkey, n, mk] in self.skipped:
      with suppress(CryptoError):
        if hkey:
          # Normal ratchet messages
          header = decrypt(ciphertext[:51], None, n.to_bytes(12, "little"), hkey)
        else:
          # Alice's initial messages (but Bob is already initialised)
          ephkey = Key(pkhash=ciphertext[:32])
          key = derive_symkey(ephkey.pkhash[:12], localkey, ephkey)
          header = decrypt(ciphertext[32:83], None, b"ratchet/init", key)
        self.skipped.remove([hkey, n, mk])
        return mk
    header = None
    # Try with current header key
    if self.h_recv:
      for n in range(self.Nr, self.Nr + 20):
        with suppress(CryptoError):
          header = decrypt(ciphertext[:51], None, n.to_bytes(12, "little"), self.h_recv)
          self.skip_until(n)
          break
    # Try with next header key
    if not header:
      for n in range(20):
        with suppress(CryptoError):
          header = decrypt(ciphertext[:51], None, n.to_bytes(12, "little"), self.nh_recv)
          PN = int.from_bytes(header[32:34], "little")
          self.skip_until(PN)
          self.dhstep(Key(pk=header[:32]))
          self.skip_until(n)
    if not header:
      raise CryptoError("Unable to authenticate")
    # Advance receiving chain
    self.chain_recv, mk = chainstep(self.chain_recv)
    self.Nr += 1
    return mk

  def skip_until(self, n):
    """Advance the receiving chain across all messages prior to message n."""
    while self.Nr < n:
      self.chain_recv, mk = chainstep(self.chain_recv)
      self.skipped.append([self.h_recv, self.Nr, mk])
      self.Nr += 1
