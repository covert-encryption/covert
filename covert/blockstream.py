import collections
import mmap
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress
from hashlib import sha512
from sys import stderr

from nacl.exceptions import CryptoError

from covert import chacha, pubkey, sign
from covert.cryptoheader import Header, encrypt_header
from covert.util import noncegen

BS = (1 << 20) - 19  # The maximum block size to use

def decrypt_file(auth, f, archive):
  b = BlockStream()
  b.decrypt_init(f)
  if not b.header.key:
    for a in auth:
      with suppress(CryptoError):
        b.authenticate(a)
        break
  yield from b.decrypt_blocks()
  b.verify_signatures(archive)

class BlockStream:
  def __init__(self):
    self.key = None
    self.nonce = None
    self.workers = 8
    self.executor = ThreadPoolExecutor(max_workers=self.workers)
    self.block = None
    self.blkhash = None
    self.ciphertext = None
    self.filepos = 0
    self.filelen = 0
    self.q = collections.deque()
    self.pos = 0  # Current position within ciphertext (buffer)

  def authenticate(self, anykey):
    """Attempt decryption using secret key or password hash"""
    if isinstance(anykey, pubkey.Key):
      self.header.try_key(anykey)
    else:
      self.header.try_pass(anykey)

  def decrypt_init(self, f):
    self.pos = 0
    if hasattr(f, "__len__"):
      # f can be an entire file in a buffer, or mmapped file
      self.ciphertext = memoryview(f)  # Prevent data copying on [:] operations.
      self.file = None
      self.end = len(self.ciphertext)
    else:
      # Large enough to hold a maximum size block per each worker
      self.ciphertext = memoryview(bytearray((0xFFFFFF+19) * self.workers))
      self.file = f
      self.end = 0
    size = self._read(1024)
    self.header = Header(self.ciphertext[:size])

  def _add_to_queue(self, p, extlen, aad=None):
    pos, end = p, p + extlen
    #assert isinstance(nblk, bytes) and len(nblk) == 12
    #assert isinstance(self.key, bytes) and len(self.key) == 32
    nblk = next(self.nonce)
    fut = self.executor.submit(chacha.decrypt, self.ciphertext[pos:end], aad, nblk, self.key)
    self.q.append((fut, nblk, pos, extlen))
    return end

  def _read(self, extlen):
    """Try to get at least extlen bytes after current pos cursor. Returns the number of bytes available."""
    if self.file:
      # Restart from the beginning of the buffer if the end would be reached
      if self.end + extlen > len(self.ciphertext):
        leftover = self.ciphertext[self.pos:self.end]
        self.ciphertext[:len(leftover)] = leftover
        self.pos = 0
        self.end = len(leftover)
      # Do we need to read anything?
      if self.end - self.pos < extlen:
        self.end += self.file.readinto(self.ciphertext[self.end:self.pos + extlen])
        size = self.end - self.pos
      else:
        size = extlen
    else:
      # MMAP is super easy
      size = min(extlen, len(self.ciphertext) - self.pos)
    return size

  def decrypt_blocks(self):
    if not self.header.key:
      raise ValueError("Not authenticated")
    self.key = self.header.key
    self.nonce = noncegen(self.header.nonce)
    self.blkhash = b""
    self.pos = self.header.block0pos
    header = bytes(self.ciphertext[:self.header.block0pos])
    self.pos = self._add_to_queue(self.pos, self.header.block0len + 19, aad=header)
    nextlen = BS
    while nextlen:
      # Stream blocks into worker threads
      while len(self.q) < self.workers:
        # Guessing block length based on the nextlen which may be from a few blocks behind
        extlen = self._read(nextlen + 19)
        if extlen:
          self.pos = self._add_to_queue(self.pos, extlen)
        if extlen < 1024:
          break # EOF or need a longer block before queuing any more
      # Wait for results, and retry if blklen was misguessed
      while self.q:
        fut, nblk, p, elen = self.q.popleft()
        try:
          block = memoryview(fut.result())
          nextlen = int.from_bytes(block[-3:], "little")
          self.blkhash = sha512(self.blkhash + self.ciphertext[p + elen - 16:p + elen]).digest()
          self.filepos += len(block) + 16
          yield block[:-3]
          if len(self.q) < self.workers:
            break
        except CryptoError:
          # Reset the queue and try again at failing pos with new nextlen if available
          for qq in self.q:
            qq[0].cancel()
          self.q.clear()
          extlen = nextlen + 19
          if elen == extlen:
            raise CryptoError(f"Failed to decrypt block {self.key.hex()} {nblk.hex()} at ({self.ciphertext[p:p+extlen].hex()})[{p}:{p + extlen}]") from None
          self.nonce = noncegen(nblk)
          pos = self._add_to_queue(p, extlen)
    for qq in self.q:
      # Restore file position and nonce to the first unused block
      if qq is self.q[0]:
        self.nonce = noncegen(qq[1])
        self.pos = qq[2]
      # Cancel all jobs still in queue
      qq[0].cancel()


  def verify_signatures(self, a):
    a.filehash = self.blkhash
    a.signatures = []
    # Signature verification
    if a.index.get('s'):
      signatures = [pubkey.Key(edpk=k) for k in a.index['s']]
      for key in signatures:
        sz = self._read(self.end - self.pos + 80)
        if sz < 80:
          raise ValueError(f"Missing signature block (needed 80 bytes, got {sz})")
        sigblock = self.ciphertext[self.pos:self.pos + 80]
        self.pos += 80
        nsig = sha512(self.blkhash + key.pk).digest()[:12]
        ksig = self.blkhash[:32]
        try:
          signature = chacha.decrypt(sigblock, None, nsig, ksig)
        except CryptoError:
          a.signatures.append((False, key, 'Signature corrupted or data manipulated'))
          continue
        try:
          sign.verify(key, self.blkhash, signature)
          a.signatures.append((True, key, 'Signature verified'))
        except CryptoError:
          a.signatures.append((False, key, 'Forged signature'))


class Block:

  def __init__(self, maxlen=BS, aad=None):
    self.cipher = memoryview(bytearray(maxlen + 19))
    self.data = self.cipher[:-19]
    self.len = None
    self.pos = 0
    self.aad = aad
    self.nextlen = None

  @property
  def spaceleft(self):
    maxlen = self.len or len(self.data)
    return maxlen - self.pos

  def consume(self, data):
    ld, ls = len(data), self.spaceleft
    if ld <= ls:
      self.data[self.pos:self.pos + ld] = data
      self.pos += ld
    else:
      self.data[self.pos:self.pos + ls] = data[:ls]
      self.pos += ls
    return data[ls:]

  def finalize(self, nextlen, n, key):
    if self.len and self.pos < self.len:
      raise Exception(f"Block with {self.len=} finalized with only {self.pos=}.")
    self.cipher = self.cipher[:self.pos + 19]
    self.cipher[self.pos:self.pos + 3] = nextlen.to_bytes(3, "little")
    chacha.encrypt_into(self.cipher, self.cipher[:-16], self.aad, n, key)
    return self.cipher


def encrypt_file(auth, blockinput, a):
  identities = auth[3]
  header, nonce, key = encrypt_header(auth)
  block = Block(maxlen=1024 - len(header) - 19, aad=header)
  queue = deque()
  yield header
  blkhash = b""

  with ThreadPoolExecutor(max_workers=8) as executor:
    futures = deque()
    run = True
    nextlen = None
    while run:
      # Run block input in a thread concurrently with any encryption jobs
      blockinput(block)
      if block.pos:
        queue.append(block)
        block = Block()
      else:
        run = False

      # Run encryption jobs in threads
      while len(queue) > 1 or queue and (queue[0].nextlen or not run):
        out = queue.popleft()
        if nextlen and nextlen != out.pos:
          raise ValueError(f'Previous block had {nextlen=} but now we have size {out.pos=}')
        nextlen = out.nextlen or (queue[0].pos if queue else 0)
        futures.append(executor.submit(Block.finalize, out, nextlen, next(nonce), key))

      # Yield results of any finished jobs, or wait for completion as needed
      while futures and (len(futures) > 8 or not run):
        ciphertext = futures.popleft().result()
        blkhash = sha512(blkhash + ciphertext[-16:]).digest()
        yield ciphertext

  # Special case for empty data, add an empty initial/final block so that the file will decrypt
  if nextlen is None:
    block = Block(0, aad=header).finalize(0, next(nonce), key)
    blkhash = sha512(blkhash + block[-16:]).digest()
    yield block

  a.filehash = blkhash
  # Add signature blocks
  for key in identities:
    signature = sign.signature(key, blkhash)
    nsig = sha512(blkhash + key.pk).digest()[:12]
    ksig = blkhash[:32]
    yield chacha.encrypt(signature, None, nsig, ksig)
