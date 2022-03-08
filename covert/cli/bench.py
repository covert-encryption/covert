import mmap
from time import perf_counter

from covert.archive import Archive
from covert.blockstream import decrypt_file, encrypt_file


def main_bench(args):

  def noop_read(block):
    nonlocal dataleft
    block.pos = min(block.spaceleft, dataleft)
    dataleft -= block.pos

  datasize = int(1e9)
  a = Archive()

  # Count ciphertext size and preallocate mmapped memory
  dataleft = datasize
  size = sum(len(block) for block in encrypt_file((True, [], [], []), noop_read, a))
  ciphertext = mmap.mmap(-1, size)
  ciphertext[:] = bytes(size)

  rounds = 3
  enctotal = dectotal = 0
  for i in range(rounds):
    print("ENC", end="", flush=True)
    dataleft, size = datasize, 0
    t0 = perf_counter()
    for block in encrypt_file((True, [], [], []), noop_read, a):
      newsize = size + len(block)
      # There is a data copy here, similar to what happens on file.write() calls.
      ciphertext[size:newsize] = block
      size = newsize
    dur = perf_counter() - t0
    enctotal += dur
    print(f"{datasize / dur * 1e-6:6.0f} MB/s", end="", flush=True)

    print("  ➤   DEC", end="", flush=True)
    t0 = perf_counter()
    for data in decrypt_file(([], [], []), ciphertext, a):
      pass
    dur = perf_counter() - t0
    dectotal += dur
    print(f"{datasize / dur * 1e-6:6.0f} MB/s")

  ciphertext.close()
  print(f"Ran {rounds} cycles, each encrypting and then decrypting {datasize * 1e-6:.0f} MB in RAM.\n")
  print(f"Average encryption {rounds * size / enctotal * 1e-6:6.0f} MB/s")
  print(f"Average decryption {rounds * size / dectotal * 1e-6:6.0f} MB/s")
