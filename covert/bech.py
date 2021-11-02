from enum import Enum


class Encoding(Enum):
  """Enumeration type to list the various supported encodings."""

  BECH32 = 1
  BECH32M = 2


CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BECH32M_CONST = 0x2BC830A3


def bech32_polymod(values):
  """Internal function that computes the Bech32 checksum."""
  generator = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
  chk = 1
  for value in values:
    top = chk >> 25
    chk = (chk & 0x1FFFFFF) << 5 ^ value
    for i in range(5):
      chk ^= generator[i] if ((top >> i) & 1) else 0
  return chk


def bech32_hrp_expand(hrp):
  """Expand the HRP into values for checksum computation."""
  return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def bech32_verify_checksum(hrp, data):
  """Verify a checksum given HRP and converted data characters."""
  const = bech32_polymod(bech32_hrp_expand(hrp) + data)
  if const == 1:
    return Encoding.BECH32
  if const == BECH32M_CONST:
    return Encoding.BECH32M
  return None


def bech32_create_checksum(hrp, data, spec):
  """Compute the checksum values given HRP and data."""
  values = bech32_hrp_expand(hrp) + data
  const = BECH32M_CONST if spec == Encoding.BECH32M else 1
  polymod = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ const
  return [(polymod >> 5 * (5-i)) & 31 for i in range(6)]


def bech32_encode(hrp, data, spec):
  """Compute a Bech32 string given HRP and data values."""
  combined = data + bech32_create_checksum(hrp, data, spec)
  return hrp + "1" + "".join([CHARSET[d] for d in combined])


def bech32_decode(bech):
  """Validate a Bech32/Bech32m string, and determine HRP and data."""
  if (any(ord(x) < 33 or ord(x) > 126 for x in bech)) or (bech.lower() != bech and bech.upper() != bech):
    return (None, None, None)
  bech = bech.lower()
  pos = bech.rfind("1")
  if pos < 1 or pos + 7 > len(bech) or len(bech) > 90:
    return (None, None, None)
  if not all(x in CHARSET for x in bech[pos + 1:]):
    return (None, None, None)
  hrp = bech[:pos]
  data = [CHARSET.find(x) for x in bech[pos + 1:]]
  spec = bech32_verify_checksum(hrp, data)
  if spec is None:
    return (None, None, None)
  return (hrp, data[:-6], spec)


def decode(hrp, addr):
  hrpgot, data, spec = bech32_decode(addr)
  if hrpgot != hrp:
    raise ValueError(f"Bech32 HRP mismatch, wanted {hrp} but got {hrpgot}")
  # Convert from 5-bit left-aligned array to 8 bit bytes
  value = sum(d << 5 * i for i, d in enumerate(reversed(data)))
  return (value >> len(data) * 5 % 8).to_bytes(len(data) * 5 // 8, "big")


def encode(hrp, databytes):
  l = (len(databytes) * 8 + 4) // 5
  value = int.from_bytes(databytes, "big") << l * 5 % 8
  data = [(value >> 5 * i) & 0b11111 for i in reversed(range(l))]
  ret = bech32_encode(hrp, data, Encoding.BECH32)
  if decode(hrp, ret) != databytes:
    raise Exception("Bech32 encode/decode failed.")
  return ret
