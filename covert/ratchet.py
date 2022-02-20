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
    self.root = derive_symkey(b"ratchet/init", localkey, peerkey)
    self.localkey = localkey
    self._tock(peerkey)

  def init_bob(self, localkey, peerkey):
    self.root = derive_symkey(b"ratchet/init", localkey, peerkey)
    self.localkey = localkey
    self._tick(peerkey)

  def dhstep(self, peerkey):
    """ECDH ratchet step, when message with new header key is received."""
    self.PN = self.Ns
    self.Ns = self.Nr = 0
    self.h_send = self.nh_send
    self.h_recv = self.nh_recv
    self._tick(peerkey)
    self.localkey = Key()
    self._tock(peerkey)

  def _tick(self, peerkey):
    self.root, self.chain_recv = chainstep(self.root, derive_symkey(b"", self.localkey, peerkey))
    _, self.nh_recv = chainstep(self.root, b"hkey")

  def _tock(self, peerkey):
    self.root, self.chain_send = chainstep(self.root, derive_symkey(b"", self.localkey, peerkey))
    _, self.nh_send = chainstep(self.root, b"hkey")

  def send(self, peerkey):
    f = 1  # Flags: 1 means signature
    if not self.chain_recv:
      ephkey = Key()
      key = derive_symkey(ephkey.pkhash[:12], self.localkey, peerkey)
      header = ephkey.pkhash + encrypt(self.localkey.pk + (self.Ns & 0xFFFF).to_bytes(2, "little") + f.to_bytes(1, "little"), None, b"ratchet/init", key)
    else:
      header = encrypt(self.localkey.pk + self.PN.to_bytes(2, "little") + f.to_bytes(1, "little"), None, self.Ns.to_bytes(12, "little"), self.h_send)
    self.chain_send, mk = chainstep(self.chain_send)
    self.Ns += 1
    return header, mk

  def receive(self, ciphertext):
    hkey = self.h_recv
    # Try skipped keys
    for [hkey, n, mk] in self.skipped:
      with suppress(CryptoError):
        header = decrypt(ciphertext[:35 + 16], None, n.to_bytes(12, "little"), self.h_recv)
        self.skipped.remove([hkey, n, mk])
        return mk
    if self.h_recv:
      # Try with old header key
      for n in range(self.Nr, self.Nr + 20):
        with suppress(CryptoError):
          header = decrypt(ciphertext[:35 + 16], None, n.to_bytes(12, "little"), self.h_recv)
          self.skip_messages(n)
    else:
      # Try with next header key
      for n in range(20):
        with suppress(CryptoError):
          header = decrypt(ciphertext[:35 + 16], None, n.to_bytes(12, "little"), self.nh_recv)
          PN = int.from_bytes(header[32:34], "little")
          self.skip_until(PN)
          self.dhstep(Key(pk=header[:32]))
          self.skip_until(n)
    self.chain_recv, mk = chainstep(self.chain_recv)
    self.Nr += 1
    return mk

  def skip_until(self, n):
    while self.Nr < n:
      self.chain_recv, mk = chainstep(self.chain_recv)
      skipped.push([self.h_recv, self.Nr, mk])
      self.Nr += 1

# Header prior to first ratchet reply (Alice's initial messages)
# nonce = b"ratchet/init"
# pubkey:   sha(nonce + dh(eph, idB))
# x3dh:     sha(dh(eph, idB) + dh(eph, skB) [+ dh(eph, otB)])
# root key = dhstep(idA, skB or idB)
#[eph:32]{[pk:32][n:2][f:1][nextlen:3]}[tag:16]

# Normal ratchet header
# nonce = Ns
#{[dh:32][pn:2][f:1][nextlen:3]}[tag:16]
