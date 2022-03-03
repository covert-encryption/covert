from __future__ import annotations

from functools import cached_property
from typing import Optional

from .scalar import fe, minus1, one, p, q, sqrtm1, zero
from .util import clamp, clamp_dirty, sha, tobytes, toint, tointsign

# Twisted Edwards curve: a x2 + y2 = 1 + d x2 y2
# Ed25519 constants:
a, d = minus1, -fe(121665) / fe(121666)

# Points are represented as tuples (X, Y, Z, T) of extended
# coordinates, with x = X/Z, y = Y/Z, x*y = T/Z

class EdPoint:
  def __init__(self, x: fe, y: fe, z: fe = one, t: Optional[fe] = None):
    # Expand to projective coordinates for faster adds
    self.X = x
    self.Y = y
    self.Z = z
    self.T = x * y if t is None else t

  @staticmethod
  def from_montbytes(b) -> EdPoint:
    """Convert from Curve25519 pk, using the high bit as x coordinate sign."""
    u, sign = tointsign(b)
    return EdPoint.from_mont(fe(u), sign)

  @staticmethod
  def from_mont(u: fe, ednegative: bool) -> EdPoint:
    """Convert from Curve25519 u coordinate and a sign for Ed25519"""
    if u == minus1:
      # Custom handling of two points with no birational mapping
      return ZERO
    return EdPoint.from_y((u - one) / (u + one), ednegative)

  @staticmethod
  def from_bytes(b) -> EdPoint:
    """Read standard Ed25519 public key"""
    val, sign = tointsign(b)
    return EdPoint.from_y(fe(val), sign)

  @staticmethod
  def from_y(y: fe, negative=False) -> EdPoint:
    """Restore from a y coordinate and an is_negative flag"""
    x2 = (y.sq - one) / (d * y.sq + one)
    if not x2.is_square: raise ValueError("Not a curve point on Ed25519")
    p = EdPoint(x2.sqrt, y)
    return p if p.is_negative == negative else -p

  @cached_property
  def mont(self) -> fe:
    """Convert the y coordinate into a Curve25519 u coordinate. sign is not included."""
    if self.y == one: return minus1
    return (one + self.y) / (one - self.y)

  @cached_property
  def montbytes_sign(self) -> bytes:
    """Provides a 32-byte CUrve25519 compatible pk with sign on the high bit"""
    return tobytes((self.is_negative << 255) + self.mont.val)

  @cached_property
  def montbytes(self) -> bytes:
    """Provides a 32-byte Curve25519 pk with zero high bit"""
    return tobytes(self.mont.val)

  def __repr__(self): return point_name(self)
  def __str__(self): return bytes(self).hex()
  def __bytes__(self): return tobytes(self.y.val + (self.is_negative << 255))
  def __hash__(self): return self.y.val
  def __abs__(self): return -self if self.is_negative else self

  @cached_property
  def norm(self) -> EdPoint:
    """Return a normalized point, with Z=1."""
    return EdPoint.from_y(self.y, self.is_negative)

  @cached_property
  def is_negative(self) -> bool:
    """Return the parity of the x coordinate, aka the sign."""
    # self.x is zero only for ZERO and LO[4], and for the latter this returns True
    return self.x.bit(0) if self.x.val else self.y.is_negative

  @cached_property
  def undirty(self) -> EdPoint:
    """Project a dirty point to its corresponding prime group point"""
    return (self if self.subgroup == 0 else self - LO[self.subgroup]).norm

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

# Neutral element
ZERO = EdPoint(zero, one)

# Base point (prime group generator)
G = EdPoint.from_y(fe(4) / fe(5), False)

# Low order generator
L = EdPoint.from_y((minus1 * ((d + one).sqrt + one) / d).sqrt, False)

# All low order points and an index lookup to find P's subgroup by q * P
LO = [i * L for i in range(8)]
LO_index = [(i * pow(q, -1, 8)) % 8 for i in range(8)]

# Dirty generator (randomises subgroups when multiplied by 0..8*q but is compatible with G)
D = G + LO[1]

def secret_scalar(edsk: bytes) -> int:
  """
  Converts Ed25519 secret key bytes to a clamped scalar.

  Note:
    Public key is edsk_scalar(edsk) * G  (for both Edwards and Montgomery)
    Curve25519 sk = tobytes(edsk_scalar(edsk))
  """
  # Sodium concatenates the public key, making it 64 bytes
  if len(edsk) not in (32, 64): raise ValueError("Invalid length for edsk")
  return clamp(sha(edsk[:32]))

def dirty_scalar(edsk) -> int:
  """
  Converts Ed25519 secret key bytes to a partially clamped scalar.

  dirty_scalar(edsk) * D = standard public key + random low order point
  """
  # High bits set as usual but the three low bits are not cleared
  if len(edsk) not in (32, 64): raise ValueError("Invalid length for edsk")
  return clamp_dirty(sha(edsk[:32]))


def point_name(P: EdPoint) -> str:
  """Return variable names rather than xy coordinates for any constants defined here"""
  for name, val in globals().items():
    if isinstance(val, EdPoint) and P == val:
      return name
  for i, val in enumerate(LO):
    if P == val:
      return f"LO[{i}]"
  return f"EdPoint({P.x!r}, {P.y!r})"
