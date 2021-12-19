from secrets import token_bytes

import nacl.bindings as sodium
import pytest

from covert.elliptic import *


def test_fe():
  assert one + zero == one
  assert zero - one == minus1
  assert fe(1234) / fe(324123) == (fe(324123) / fe(1234)).inv
  assert sqrtm1 * sqrtm1 == -one
  assert repr(fe(1234)) == "fe(1234)"
  assert repr(fe(-1)) == "minus1"
  assert bytes(zero) == bytes(32)
  assert str(one) == "01" + 31 * "00"

  x = fe(toint(token_bytes(32)))
  assert x.sq.sqrt == abs(x)
  assert x.inv.inv == x
  assert x**3 == x * x * x
  assert x * fe(2) == x + x
  assert x * fe(2) != x

  with pytest.raises(ValueError):
    fe(2).sqrt


def test_ed():
  assert G == EdPoint.from_xbytes((9).to_bytes(32, "little"))

  assert repr(ZERO) == "EdPoint(\n  zero,\n  one,\n  one,\n  zero,\n)"
  assert str(ZERO) == "01" + 31 * "00"

  edpk, edsk = sodium.crypto_sign_keypair()
  k = edsk_scalar(edsk)
  K = k * G
  assert bytes(K).hex() == edpk.hex()


def test_lo():
  # Dirty generator
  assert 2 * D == 2 * G + 2 * L
  assert 8 * G == 8 * D
  assert 12 * G != 12 * D

  # Testing properties
  assert ZERO.is_low_order
  assert ZERO.subgroup == 0
  assert not ZERO.is_prime_group

  assert G.is_prime_group
  assert not G.is_low_order
  assert G.subgroup == 0

  assert not L.is_prime_group
  assert L.is_low_order
  assert L.subgroup == 1

  assert not D.is_prime_group
  assert not D.is_low_order
  assert D.subgroup == 1

  # Low order points
  assert LO[0] == ZERO
  assert LO[1] == L
  for i, P in enumerate(LO):
    assert 8 * P == ZERO
    assert P.is_low_order
    assert not P.is_prime_group
    assert P.subgroup == i

    s = edsk_scalar(token_bytes(32))
    Q = s * G + P
    assert not Q.is_low_order
    assert Q.subgroup == i

  # Dirty point generation
  s = toint(token_bytes(32)) % (8 * q)
  P = s * G
  Q = s * D
  assert Q.subgroup == s % 8
  assert Q == P + LO[Q.subgroup]


def test_sign_eddsa():
  """Test signatures using standard Ed25519"""
  msg1 = b"test message"
  msg2 = b"Test message"
  edpk, edsk = sodium.crypto_sign_keypair()
  sig1 = ed_sign(edsk, msg1)
  sig2 = ed_sign(edsk, msg2)
  assert len(sig1) == 64
  assert sig1 != sig2
  ed_verify(edpk, msg1, sig1)
  ed_verify(edpk, msg2, sig2)
  with pytest.raises(ValueError):
    ed_verify(edpk, msg2, sig1)
  with pytest.raises(ValueError):
    ed_verify(edpk, msg1, sig2)


def test_sign_xeddsa():
  """Test signatures using Signal's XEd25519 scheme"""
  msg1 = b"test message"
  msg2 = b"Test message"
  nonce = token_bytes(64)
  # Using only Curve25519 keys for this
  pk, sk = sodium.crypto_box_keypair()
  sig1 = xed_sign(sk, msg1, nonce)
  sig2 = xed_sign(sk, msg2, nonce)
  assert len(sig1) == 64
  assert sig1 != sig2
  xed_verify(pk, msg1, sig1)
  xed_verify(pk, msg2, sig2)
  with pytest.raises(ValueError):
    xed_verify(pk, msg2, sig1)
  with pytest.raises(ValueError):
    xed_verify(pk, msg1, sig2)


def test_elligator():
  while True:
    pk, sk = sodium.crypto_box_keypair()
    if ishashable(pk):
      break
  hidden = keyhash(pk)
  pk2 = unhash(hidden)
  assert pk == pk2
