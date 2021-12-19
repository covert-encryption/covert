from __future__ import annotations

from functools import cached_property

from .scalar import fe, minus1, one, p, q, sqrtm1, zero
from .util import clamp, sha, tobytes, toint

# Ed25519 curve constant -x2 + y2 = 1 - d x2 y2
d = fe(-121665) / fe(121666)

# Points are represented as tuples (X, Y, Z, T) of extended
# coordinates, with x = X/Z, y = Y/Z, x*y = T/Z

class EdPoint:
  @staticmethod
  def from_xbytes(b) -> EdPoint:
    """Convert from Curve25519 pk, using the high bit as x coordinate sign."""
    val = toint(b)
    sign = 1 << 255 & val
    u = fe(val ^ sign)
    y = (u - one) / (u + one)
    return EdPoint.from_y(y, bool(sign))

  @staticmethod
  def from_bytes(b) -> EdPoint:
    """Read standard Ed25519 public key"""
    val = toint(b)
    sign = 1 << 255 & val
    return EdPoint.from_y(fe(val ^ sign), bool(sign))

  @staticmethod
  def from_y(y: fe, sign=False) -> EdPoint:
    # Recover x
    x = ((y.sq - one) / (d * y.sq + one)).sqrt
    if sign and x == zero:
      raise ValueError(f"Ed25519 x is zero, cannot satisfy {sign=}")
    if x.bit(0) != sign: x = -x
    return EdPoint(x, y, one, x * y)

  @staticmethod
  def from_xy(x: fe, y: fe) -> EdPoint:
    return EdPoint(x, y, one, x * y)

  def __init__(self, X: fe, Y: fe, Z: fe, T: fe):
    self.X = X
    self.Y = Y
    self.Z = Z
    self.T = T
    assert self.x * self.y == self.T / self.Z

  def __repr__(self):
    return f"EdPoint(\n  {self.X!r},\n  {self.Y!r},\n  {self.Z!r},\n  {self.T!r},\n)"

  def __str__(self):
    return bytes(self).hex()

  def __bytes__(self):
    return tobytes(self.y.val + (self.x.val & 1) * (1 << 255))

  def __hash__(self): return self.Y.val   # Faster then truly unique values

  @cached_property
  def norm(self) -> EdPoint:
    """Return a normalized point, with Z=1."""
    return EdPoint.from_y(self.y, self.sign)

  @cached_property
  def sign(self) -> bool:
    """Return the sign of the x coordinate, aka the sign."""
    return bool(self.x.val & 1)

  @cached_property
  def subgroup(self) -> int:
    """Return the subgroup (0..7) where 0 is the prime group"""
    return LO_index[LO.index(q * self)]

  @cached_property
  def is_low_order(self) -> bool: return self in LO

  @cached_property
  def is_prime_group(self) -> bool: return not self.is_low_order and self.subgroup == 0

  @cached_property
  def x(self) -> fe: return self.X / self.Z

  @cached_property
  def y(self) -> fe: return self.Y / self.Z

  def __add__(self, othr: EdPoint) -> EdPoint:
    if not isinstance(othr, EdPoint): return NotImplemented
    A = (self.Y - self.X) * (othr.Y - othr.X)
    B = (self.Y + self.X) * (othr.Y + othr.X)
    C = fe(2) * self.T * othr.T * d
    D = fe(2) * self.Z * othr.Z
    E, F, G, H = B - A, D - C, D + C, B + A
    return EdPoint(E * F, G * H, F * G, E * H)

  def __sub__(self, othr: EdPoint) -> EdPoint:
    return self + -othr

  def __neg__(self) -> EdPoint:
    return EdPoint(-self.X, self.Y, self.Z, -self.T)

  def __mul__(self, s: int) -> EdPoint:
    """Multiply the point by scalar (secret key)."""
    if not isinstance(s, int): return NotImplemented
    Q = ZERO  # Neutral element
    P = self
    # Modulo s first to make multiplication faster (8 * q rather than q to support non-prime subgroups)
    s %= 8 * q
    while s > 0:
      if s & 1: Q += P
      P += P
      s >>= 1
    return Q.norm

  def __rmul__(self, s: int) -> EdPoint:
    return self * s

  def __eq__(self, othr):
    if not isinstance(othr, EdPoint): raise TypeError(f"EdPoints cannot be compared with {type(othr)}")
    # x1 / z1 == x2 / z2  <==>  x1 * z2 == x2 * z1
    return (
      (self.X * othr.Z - othr.X * self.Z) == zero and
      (self.Y * othr.Z - othr.Y * self.Z) == zero
    )

  @cached_property
  def x25519(self) -> fe:
    """Convert the y coordinate into a Curve25519 u coordinate. sign is not included."""
    return (one + self.Y) / (one - self.Y)

  @cached_property
  def xbytes(self) -> bytes:
    """Provides a 32-byte X25519 compatible pk with sign on the high bit"""
    return tobytes((self.sign << 255) + self.x25519.val)

  @cached_property
  def xbytes_standard(self) -> bytes:
    """Provides a 32-byte X25519 pk with zero high bit"""
    return tobytes(self.x25519.val)

# Neutral element
ZERO = EdPoint(zero, one, one, zero)

# Base point (prime group generator)
G = EdPoint.from_y(fe(4) / fe(5), False)

# Low order generator
L = EdPoint.from_y((minus1 * ((d + one).sqrt + one) / d).sqrt, False)

# All low order points and an index lookup to find P's subgroup by q * P
LO = [i * L for i in range(8)]
LO_index = [(i * pow(q, -1, 8)) % 8 for i in range(8)]

# Dirty generator (randomises subgroups when multiplied by 0..8*q but is compatible with G)
D = G + LO[1]

def edsk_scalar(edsk) -> int:
  """Converts Ed25519 secret key bytes to a clamped scalar"""
  # Sodium concatenates the public key, making it 64 bytes
  if len(edsk) not in (32, 64): raise ValueError("Invalid length for edsk")
  return clamp(sha(edsk[:32]))
