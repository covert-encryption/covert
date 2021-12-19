# Elligator2 over Curve25519, see section 5 of
# https://www.shiftleft.org/papers/elligator/elligator.pdf

from secrets import randbits
from typing import Tuple

from .scalar import fe, one, p, sqrtm1, zero

# Curve25519 constant
A = fe(486662)

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
vfactor = ufactor.sqrt


def fast_hash_to_curve(r: fe) -> Tuple[fe, fe]:
  """Convert a 254-bit hash into a pair of curve coordinates"""
  t1 = r**2 * non_square  # r1
  u = t1 + one  # r2
  t2 = u**2
  t3 = (A**2 * t1 - t2) * A  # numerator
  t1 = t2 * u  # denominator
  t1 = (t3 * t1).invsqrt
  u = r**2 * ufactor
  v = r * vfactor
  if t1.is_square:
    u, v = one, one
  v *= t3 * t1
  u *= -A * t3 * t2 * t1**2
  if t1.is_square != v.is_negative:  # XOR
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
  isr = r.invsqrt
  if not isr.is_square:
    raise ValueError("The point cannot be mapped.")
  if v_is_negative: u = t
  r = u * isr
  r = abs(r)
  return r


# Unlike the paper, curve coordinates are called (u, v) to follow
# established conventions. Thus, "v" in the paper is called "w" here.
def hash_to_curve(r: fe) -> Tuple[fe, fe]:
  """Reference implementation of S to point"""
  w = -A / (one + non_square * r**2)
  e = (w**3 + A * w**2 + w).chi
  u = e*w - (one - e) * (A//2)
  v = -e * (u**3 + A * u**2 + u).sqrt
  return u, v


# Computes the representative of a point, straight from the paper.
def curve_to_hash(u: fe, v_is_negative: bool) -> fe:
  """Reference implementation of point to S"""
  if not can_curve_to_hash(u):
    raise ValueError('cannot curve to hash')
  sq1 = (-u / (non_square * (u+A))).sqrt
  sq2 = (-(u + A) / (non_square * u)).sqrt
  return sq2 if v_is_negative else sq1


def can_curve_to_hash(u: fe) -> bool:
  """Test if a point is hashable."""  # Straight from the paper.
  return u != -A and (-non_square * u * (u + A)).is_square


def keyhash(pk: bytes) -> bytes:
  """Convert a public key to obfuscated elligator2 hash."""
  assert len(pk) == 32
  # Curve25519 keys are 255 bits but only half of the values are valid
  # curve points. More over, only 1/8 of those points are in the prime group,
  # which is used by all standard operations and can be easily tested for.
  #
  # Elligator2 also rejects half of the keys that would otherwise be valid,
  # requiring retried key generation until successful.

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
