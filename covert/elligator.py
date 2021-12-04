# Based on code by Loup Vaillant and Andrew Moon (public domain, no warranties)
# https://github.com/LoupVaillant/Monocypher/blob/master/tests/gen/elligator.py

# Elligator2 over Curve25519, see section 5 of
# https://www.shiftleft.org/papers/elligator/elligator.pdf

from __future__ import annotations

from secrets import randbits
from typing import Tuple


class fe:
  """A prime field scalar modulo p = 2^255 - 19"""
  p = 2**255 - 19

  def __init__(self, x: int):
    self.val = x % self.p

  # Basic arithmetic operations
  def __neg__(self):
    return fe(-self.val)

  def __add__(self, o: fe):
    return fe(self.val + o.val)

  def __sub__(self, o: fe):
    return fe(self.val - o.val)

  def __mul__(self, o: fe):
    return fe((self.val * o.val) % self.p)

  def __truediv__(self, o: fe):
    return fe((self.val * o.invert().val) % self.p)

  def __floordiv__(self, o: int):
    return fe(self.val // o)

  def __pow__(self, s: int):
    return fe(pow(self.val, s, self.p))

  def invert(self):
    return fe(pow(self.val, self.p - 2, self.p))

  def __eq__(self, other):
    if not isinstance(other, fe): return NotImplemented
    return self.val % self.p == other.val % self.p

  def __ne__(self, other):
    if not isinstance(other, fe): return NotImplemented
    return self.val % self.p != other.val % self.p

  def is_positive(self):
    return self.val % self.p <= (p-1) // 2

  def is_negative(self):
    return self.val % self.p > (p-1) // 2

  def __abs__(self):
    return self if self.is_positive() else -self

  def __repr__(self):
    return f"fe({self.val})"

  def __str__(self):
    """Little endian hex string"""
    return bytes(self).hex()

  def __bytes__(self):
    return self.val.to_bytes(32, 'little')


# Curve25519 constants
p = fe.p
A = fe(486662)


# Legendre symbol:
# -  0 if n is zero
# -  1 if n is a non-zero square
# - -1 if n is not a square
# We take for granted that n^((p-1)/2) does what we want
def chi(n: fe) -> fe:
  """Legendre symbol"""
  return n**((p-1) // 2)


def is_square(n: fe) -> bool:
  return n == fe(0) or chi(n) == fe(1)


# square root of -1
sqrtm1 = abs(fe(2)**((p-1) // 4))
assert sqrtm1 * sqrtm1 == fe(-1)


def sqrt(n):
  """The square root of n. Raises ValueError otherwise."""
  if not is_square(n): raise ValueError('Not a square!')
  # Note that p is congruent to 5 modulo 8, so (p+3)/8 is an integer.
  # If n is zero, then n^((p+3)/8) is zero (zero is its own square root).
  root = n**((p+3) // 8)
  # We then choose the positive square root, between 0 and (p-1)/2
  if root * root != n: root = (root * sqrtm1)
  assert root * root == n
  return abs(root)


# Inverse square root.
# Returns (sqrt(1/x)       , True ) if x is non-zero square.
# Returns (sqrt(sqrt(-1)/x), False) if x is not a square.
# Returns (0               , False) if x is zero.
# We do not guarantee the sign of the square root.
def invsqrt(x: fe) -> Tuple[fe, bool]:
  """Fast 1/sqrt(x) on Curve25519, more black magic than Carmack's"""
  isr = x**((p-5) // 8)
  quartic = x * isr**2
  if quartic == fe(-1) or quartic == -sqrtm1:
    isr = isr * sqrtm1
  is_square = quartic == fe(1) or quartic == fe(-1)
  return isr, is_square


# Arbitrary non square, typically chosen to minimise computation.
# 2 and sqrt(-1) both work fairly well, but 2 seems to be more popular.
# We stick to 2 for compatibility.
non_square = fe(2)

# From the paper:
# w = -A / (fe(1) + non_square * r^2)
# e = chi(w^3 + A*w^2 + w)
# u = e*w - (fe(1)-e)*(A//2)
# v = -e * sqrt(u^3 + A*u^2 + u)
ufactor = -non_square * sqrtm1
vfactor = sqrt(ufactor)


def fast_hash_to_curve(r: fe) -> Tuple[fe, fe]:
  """Convert a 254-bit hash into a pair of curve coordinates"""
  t1 = r**2 * non_square  # r1
  u = t1 + fe(1)  # r2
  t2 = u**2
  t3 = (A**2 * t1 - t2) * A  # numerator
  t1 = t2 * u  # denominator
  t1, is_square = invsqrt(t3 * t1)
  u = r**2 * ufactor
  v = r * vfactor
  if is_square:
    u, v = fe(1), fe(1)
  v *= t3 * t1
  t1 = t1**2
  u *= -A * t3 * t2 * t1
  if is_square != v.is_negative():  # XOR
    v = -v
  return u, v


# From the paper:
# Let sq = -non_square * u * (u+A)
# if sq is not a square, or u = -A, there is no mapping
# Assuming there is a mapping:
#   if v is positive: r = sqrt(-(u+A) / u)
#   if v is negative: r = sqrt(-u / (u+A))
#
# We compute isr = invsqrt(-non_square * u * (u+A))
# if it wasn't a non-zero square, abort.
# else, isr = sqrt(-1 / (non_square * u * (u+A))
#
# This causes us to abort if u is zero, even though we shouldn't. This
# never happens in practice, because (i) a random point in the curve has
# a negligible chance of being zero, and (ii) scalar multiplication with
# a trimmed scalar *never* yields zero.
def fast_curve_to_hash(u: fe, v_is_negative: bool) -> fe:
  """Convert a curve point into a pseudorandom 254 bit value"""
  t = u + A
  r = -non_square * u * t
  isr, is_square = invsqrt(r)
  if not is_square:
    raise ValueError("The point cannot be mapped.")
  if v_is_negative: u = t
  r = u * isr
  r = abs(r)
  return r


# Unlike the paper, curve coordinates are called (u, v) to follow
# established conventions. Thus, "v" in the paper is called "w" here.
def hash_to_curve(r: fe) -> Tuple[fe, fe]:
  """Reference implementation of S to point"""
  w = -A / (fe(1) + non_square * r**2)
  e = chi(w**3 + A * w**2 + w)
  u = e*w - (fe(1) - e) * (A//2)
  v = -e * sqrt(u**3 + A * u**2 + u)
  return u, v


# Computes the representative of a point, straight from the paper.
def curve_to_hash(u: fe, v_is_negative: bool) -> fe:
  """Reference implementation of point to S"""
  if not can_curve_to_hash(u):
    raise ValueError('cannot curve to hash')
  sq1 = sqrt(-u / (non_square * (u+A)))
  sq2 = sqrt(-(u + A) / (non_square*u))
  if v_is_negative: return sq2
  else: return sq1


def can_curve_to_hash(u: fe) -> bool:
  """Test if a point is hashable."""  # Straight from the paper.
  return u != -A and is_square(-non_square * u * (u+A))


def keyhash(pk: bytes) -> bytes:
  """Convert a public key to obfuscated elligator2 hash."""
  assert len(pk) == 32
  # Curve25519 keys are 255 bits but only half of the values are valid
  # curve points, so random 32 bytes are a valid key only with 25 %
  # probability (a tiny bit less, actually), if no encoding is done.
  #
  # Elligator2 also rejects half of the keys that would otherwise be valid,
  # so we are left with 252 bits of entropy. The coding does, however,
  # store the v coordinate sign, despite that being unused and ignored in all
  # Curve25519 operations, producing a 253 bit coding where the value of that
  # sign changes the entire output. Even then the top two bits are always zero.
  #
  # To create pseudo-random strings, we need to inject three random bits,
  # one as the sign before hashing and two afterwards on the output.
  # These could also be used to carry information, if we had something
  # random-like to carry. Ed25519 sign bit would be a prime candidate...
  sign = bool(randbits(1))
  r = fast_curve_to_hash(fe(int.from_bytes(pk, "little")), sign)
  r.val ^= randbits(2) << 254  # Fill in the high bits
  return bytes(r)


def unhash(h: bytes) -> bytes:
  """Convert an elligator2 hash back to Curve25519 pk."""
  assert len(h) == 32
  mask = (1 << 254) - 1  # The two highest bits are not used
  r = fe(int.from_bytes(h, "little") & mask)
  u, v = fast_hash_to_curve(r)  # The v and its sign are ignored
  return bytes(u)


def ishashable(pk: bytes) -> bool:
  """
  Test if a key can be mapped (need to generate another if not).
  The key is assumed to be valid in Curve25519, not tested for.
  """
  # This is much faster than trying to run keyhash()
  assert len(pk) == 32
  u = int.from_bytes(pk, "little")
  return can_curve_to_hash(fe(u))
