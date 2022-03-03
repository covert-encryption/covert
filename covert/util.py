import platform
import re
import unicodedata
from base64 import b64decode, b64encode
from math import log
from secrets import choice, token_bytes

ARMOR_MAX_SINGLELINE = 4000  # Safe limit for line input, where 4096 may be the limit
ARMOR_MAX_SIZE = 32 << 20  # If output is a file (limit our memory usage)
TTY_MAX_SIZE = 100 << 10  # If output is a tty (limit too lengthy spam)
IS_APPLE = platform.system() == "Darwin"

def armor_decode(data: str) -> bytes:
  """Base64 decode."""
  # Fix CRLF, remove any surrounding BOM, whitespace and code block markers
  data = data.replace('\r\n', '\n').strip('\uFEFF`> \t\n')
  if not data.isascii():
    raise ValueError(f"Invalid armored encoding: data is not ASCII/Base64")
  # Strip indent and quote marks, trailing whitespace and empty lines
  lines = [line for l in data.split('\n') if (line := l.lstrip('\t >').rstrip())]
  # Empty input means empty output (will cause an error elsewhere)
  if not lines:
    return b''
  # Verify charset on all lines
  r = re.compile(f"^[A-Za-z0-9+/]+$")
  for i, line in enumerate(lines):
    if not r.match(line):
      raise ValueError(f"Invalid armored encoding: unrecognized data on line {i + 1}")
  # Verify line lengths
  l = len(lines[0])
  for i, line in enumerate(lines[:-1]):
    l2 = len(line)
    if l2 < 76 or l2 % 4 or l2 != l:
      raise ValueError(f"Invalid armored encoding: length {l2} of line {i + 1} is invalid")
  data = "".join(lines)
  padding = -len(data) % 4
  if padding == 3:
    raise ValueError(f"Invalid armored encoding: invalid length for Base64 sequence")
  # Not sure why we even bother to use the standard library after having handled all that...
  return b64decode(data + padding*'=', validate=True)


def armor_encode(data: bytes) -> str:
  """Base64 without the padding nonsense, and with adaptive line wrapping."""
  d = b64encode(data).decode().rstrip('=')
  if len(d) > ARMOR_MAX_SINGLELINE:
    # Make fingerprinting the encoding by line lengths a bit harder while still using >76
    splitlen = choice(range(76, 121, 4))
    d = '\n'.join([d[i:i + splitlen] for i in range(0, len(d), splitlen)])
  return d


def encode(s: str) -> bytes:
  """Unicode-normalizing UTF-8 encode."""
  return unicodedata.normalize("NFKC", s.lstrip("\uFEFF")).encode()


def decode_native(s: bytes) -> str:
  """Restore platform-native Unicode normalization form (e.g. for filenames)."""
  return unicodedata.normalize("NFD" if IS_APPLE else "NFKC", s.decode())


def noncegen(nonce=None):
  nonce = token_bytes(12) if nonce is None else bytes(nonce)
  l = len(nonce)
  mask = (1 << 8 * l) - 1
  while True:
    yield nonce
    # Overflow safe fast increment (152ns vs. 139ns without overflow protection)
    nonce = (int.from_bytes(nonce, "little") + 1 & mask).to_bytes(l, "little")


def xor(a, b) -> bytes:
  assert len(a) == len(b)
  l = len(a)
  a = int.from_bytes(a, "little")
  b = int.from_bytes(b, "little")
  return (a ^ b).to_bytes(l, "little")


def random_padding(size, p) -> int:
  """Calculate random padding size in bytes as (roughly) proportion p of message size."""
  if not p:
    return 0
  # Choose the amount of fixed padding to hide very short messages
  fixed_padding = max(0, int(p * 500) - size)
  # Random padding on effective size (increased for small data, decreased for gigabyte class)
  eff_size = 200 + 1e8 * log(1 + 1e-8 * (size + fixed_padding))
  r = log(1 << 65) - log(1 + 2 * int.from_bytes(token_bytes(8), "little"))
  # Apply pad-to-fixed-size for very short messages plus random padding
  return fixed_padding + int(round(r * p * eff_size))
