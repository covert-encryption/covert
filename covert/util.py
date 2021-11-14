import random
import unicodedata
from base64 import b64decode, b64encode
from math import log2
from secrets import token_bytes

ARMOR_MAX_SINGLELINE = 4000  # Safe limit for line input, where 4096 may be the limit


def armor_decode(data):
  """Base64 decode."""
  # Need to remove whitespace and backticks (if accidentally pasted) before adding padding
  data = bytes(b for b in data if b not in b' \n\r\t`')
  data = data.replace(b'-', b'+').replace(b'_', b'/')  # Support also url-safe base64
  padding = -len(data) % 4
  return b64decode(data + padding*b'=', validate=True)


def armor_encode(data):
  """Base64 without the padding nonsense, and with adaptive line wrapping."""
  data = b64encode(data).rstrip(b'=')
  if len(data) > ARMOR_MAX_SINGLELINE:
    # Make fingerprinting the encoding by line lengths a bit harder while still using >76
    splitlen = random.choice(range(76, 121, 4))
    data = b'\n'.join([data[i:i + splitlen] for i in range(0, len(data), splitlen)])
  return data


def encode(s):
  return unicodedata.normalize("NFKC", s).encode()


def noncegen(nonce=None):
  nonce = token_bytes(12) if nonce is None else bytes(nonce)
  l = len(nonce)
  mask = (1 << 8 * l) - 1
  while True:
    yield nonce
    # Overflow safe fast increment (152ns vs. 139ns without overflow protection)
    nonce = (int.from_bytes(nonce, "little") + 1 & mask).to_bytes(l, "little")


def xor(a, b):
  assert len(a) == len(b)
  l = len(a)
  a = int.from_bytes(a, "little")
  b = int.from_bytes(b, "little")
  return (a ^ b).to_bytes(l, "little")


def random_padding(total, p):
  """Calculate random padding size in bytes as (roughly) proportion p of total size."""
  if not p:
    return 0
  # Choose the amount of fixed padding to hide very short messages
  low = int(p * 200)
  padfixed = max(0, low - total)
  # Calculate a preferred mean size and randomize
  padsize = 2 + p * .7e8 * log2(1 + 1e-8 * max(low, total))
  padsize = int(round(random.expovariate(1.0 / padsize)))
  # Apply pad-to-fixed-size for very short messages plus random padding
  return padfixed + padsize
