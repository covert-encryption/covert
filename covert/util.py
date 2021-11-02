import unicodedata
from base64 import urlsafe_b64decode, urlsafe_b64encode
from secrets import token_bytes

ARMOR_MAX_SINGLELINE = 16000  # Windows console is limited to 16384
ARMOR_SPLIT_LEN = 120  # Should be a multiple of 4


def armor_decode(data):
  """URL-safe Base64 decode."""
  # Need to remove whitespace and backticks (if accidentally pasted) before adding padding
  data = bytes(b for b in data if b not in b' \n\r\t`')
  padding = -len(data) % 4
  return urlsafe_b64decode(data + padding*b'=').rstrip(b'=')


def armor_encode(data):
  """Actually URL-safe Base64 without the padding nonsense, and with line wrapping."""
  data = urlsafe_b64encode(data).rstrip(b'=')
  if len(data) > ARMOR_MAX_SINGLELINE:
    data = b'\n'.join([data[i:i + ARMOR_SPLIT_LEN] for i in range(0, len(data), ARMOR_SPLIT_LEN)])
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
