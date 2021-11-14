import collections
import mmap
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from hashlib import sha512
from sys import stderr

from nacl.exceptions import CryptoError

from covert import chacha, pubkey, sign
from covert.cryptoheader import decrypt_header, encrypt_header
from covert.util import noncegen

BS = (1 << 20) - 19  # The maximum block size to use (only affects encryption)


def decrypt_file(auth, f):
  pks = []  # FIXME: Needs to be loaded with signatures to verify (from archive)

  def add_to_queue(p, blklen, nblk):
    nonlocal pos
    pos, end = p, p + blklen
    fut = executor.submit(chacha.decrypt, ciphertext[pos:end], None, nblk, key)
    q.append((fut, nblk, pos, blklen))
    pos = end

  workers = 8
  mmapped = isinstance(f, mmap.mmap)
  if mmapped:
    ciphertext = memoryview(f)  # Prevent data copying on [:] operations.
    filelen = len(ciphertext)
  else:
    # Large enough to hold a maximum size block per each worker
    ciphertext = memoryview(bytearray((0xFFFFFF+19) * workers))
    filelen = f.readinto(ciphertext[:1024])
  block, pos, key, nonce = decrypt_header(ciphertext[:min(filelen, 1024)], auth)
  blkhash = sha512(ciphertext[:pos]).digest()
  executor = ThreadPoolExecutor(max_workers=workers)
  q = collections.deque()
  nextlen = int.from_bytes(block[-3:], "little") + 19
  yield memoryview(block)[:-3]
  while nextlen > 19:
    # Stream blocks into worker threads
    while len(q) < workers:
      # Guessing block length based on the nextlen which may be from a few blocks behind
      if mmapped:
        blklen = min(nextlen, len(ciphertext) - pos)
      else:
        # Restart from the beginning of the buffer if the end would be reached
        if pos + nextlen > len(ciphertext):
          pos = 0
        blklen = f.readinto(ciphertext[pos:pos + nextlen])
      if not blklen:
        break
      add_to_queue(pos, blklen, next(nonce))
    # Wait for results, and retry if blklen was misguessed
    while q:
      fut, nblk, p, blklen = q.popleft()
      try:
        block = memoryview(fut.result())
        nextlen = int.from_bytes(block[-3:], "little") + 19
        blkhash = sha512(blkhash + ciphertext[p + blklen - 16:p + blklen]).digest()
        yield block[:-3]
        if len(q) < workers:
          break
      except CryptoError:
        # Reset the queue and try again at failing pos with new nextlen if available
        for qq in q:
          qq[0].cancel()
        if blklen == nextlen:
          raise CryptoError(f"Failed to decrypt next block at [{p}:{p + blklen}]") from None
        q.clear()
        nonce = noncegen(nblk)
        add_to_queue(p, nextlen, nblk)

  if False:
    # Signature writing (proto)
    keys = [pubkey.sk_to_pk(pubkey.decode_sk(sk)) for sk in identities]
    keys += [pubkey.decode_pk(pk) for pk in pks]
    if mmapped:
      while len(ciphertext) - pos >= 80:
        sigblock = ciphertext[pos:pos + 80]
        pos += 80
        for pk in keys:
          nsig = sha512(blkhash + pk).digest()[:12]
          ksig = blkhash[:32]
          signature = chacha.decrypt(sigblock, None, nsig, ksig)
          try:
            sign.verify(signature, blkhash, pk)
            stderr.write(f"Verified signature {key}\n")
          except Exception:
            pass


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


def encrypt_file(auth, blockinput):
  identities = auth[3]
  header, nonce, key = encrypt_header(auth)
  block = Block(maxlen=1024 - len(header) - 19, aad=header)
  queue = deque()
  yield header
  blkhash = sha512(header).digest()

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

  # Add signature blocks
  for sk in identities:
    sk = pubkey.decode_sk(sk)
    pk = pubkey.sk_to_pk(sk)
    signature = sign.signature(sk, blkhash)
    nsig = sha512(blkhash + pk).digest()[:12]
    ksig = blkhash[:32]
    yield chacha.encrypt(signature, None, nsig, ksig)
