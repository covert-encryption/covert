from __future__ import annotations

from functools import cached_property
from typing import Union

# Field prime
p = 2**255 - 19

# Precalculate commonly needed parts of the prime
p2 = (p - 1) // 2
p4 = (p - 1) // 4
p38 = (p + 3) // 8
p58 = (p - 5) // 8

# Group order (both Ed25519 and Curve25519)
q = 2**252 + 27742317777372353535851937790883648493


class fe:
  """A prime field scalar modulo p = 2^255 - 19"""
  def __init__(self, x: int): self.val = x % p
  def __hash__(self): return self.val
  def __repr__(self): return value_name(self)
  def __str__(self): return bytes(self).hex()
  def __bytes__(self): return self.val.to_bytes(32, 'little')
  def bit(self, n: int): return bool(self.val & 1 << n)

  def __eq__(self, other):
    # Note: if we return NotImplemented, Python does object comparison and returns False
    if not isinstance(other, fe): raise TypeError(f"Cannot compare fe with {other!r}")
    return self.val == other.val

  def __abs__(self): return -self if self.is_negative else self
  def __neg__(self): return fe(-self.val)
  def __add__(self, o: fe): return fe(self.val + o.val)
  def __sub__(self, o: fe): return fe(self.val - o.val)
  def __mul__(self, o: fe): return fe((self.val * o.val) % p)

  def __truediv__(self, o: fe) -> fe:
    """Division mod p"""
    return self if o == one else fe(self.val * o.inv.val)

  def __floordiv__(self, o: int) -> fe:
    """Simple integer division"""
    return fe(self.val // o)

  def __pow__(self, s: int) -> fe:
    # Use faster cached .sq for x**2 because it is a very common operation
    return self.sq if s == 2 else fe(pow(self.val, s, p))

  @cached_property
  def inv(self) -> fe: return self**-1

  @cached_property
  def is_negative(self) -> bool: return self.val > p2

  # Legendre symbol:
  # -  0 if n is zero
  # -  1 if n is a non-zero square
  # - -1 if n is not a square
  # We take for granted that n^((p-1)/2) does what we want
  @cached_property
  def chi(self) -> fe:
    """Legendre symbol"""
    return self**p2

  @cached_property
  def sq(self) -> fe:
    """Squared"""
    x = self * self
    x.is_square = True
    return x

  @cached_property
  def is_square(self) -> bool: return self == zero or self.chi == one

  @cached_property
  def sqrt(self) -> bool:
    """The square root. Raises ValueError otherwise."""
    if not self.is_square: raise ValueError('Not a square!')
    # Note that p is congruent to 5 modulo 8, so (p+3)/8 is an integer.
    # If n is zero, then n^((p+3)/8) is zero (zero is its own square root).
    root = self**p38
    # We then choose the positive square root, between 0 and (p-1)/2
    if root * root != self: root *= sqrtm1
    assert root * root == self
    return abs(root)

  # Inverse square root.
  # Returns (sqrt(1/x)       , True ) if x is non-zero square.
  # Returns (sqrt(sqrt(-1)/x), False) if x is not a square.
  # Returns (0               , False) if x is zero.
  # We do not guarantee the sign of the square root.
  @cached_property
  def invsqrt(self) -> fe:
    """Fast 1/sqrt(x) mod p, more black magic than Carmack's"""
    isr = self**p58
    quartic = self * isr.sq
    if quartic == minus1 or quartic == -sqrtm1: isr *= sqrtm1
    isr.is_square = quartic == one or quartic == minus1
    return isr

zero, one, minus1 = fe(0), fe(1), fe(-1)

# square root of -1 (used in implementation of fe.sqrt, so cannot calculate with that)
sqrtm1 = abs(fe(2)**p4)
assert sqrtm1 * sqrtm1 == minus1


def value_name(s: fe) -> str:
  """Return variable names rather than fe(...) for any constants defined here"""
  for name, val in globals().items():
    if isinstance(val, fe) and s == val:
      return name
  for name, val in globals().items():
    if isinstance(val, fe) and s == -val:
      return f"-{name}"
  return f"fe({s.val})"
