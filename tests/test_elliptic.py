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
  assert G == EdPoint.from_montbytes((9).to_bytes(32, "little"))

  assert repr(ZERO) == "ZERO"  # EdPoint(zero, one, one, zero)
  assert str(ZERO) == "01" + 31 * "00"

  edpk, edsk = sodium.crypto_sign_keypair()
  k = secret_scalar(edsk)
  K = k * G
  assert bytes(K).hex() == edpk.hex()

def test_mont():
  assert mont.scalarmult(0, D.mont) == ZERO.mont
  assert mont.scalarmult(1, D.mont) == D.mont

  # Low order points
  Lmont = [mont.scalarmult(s, L) for s in range(8)]
  Lexpected = [ZERO.mont, L.mont, LO[2].mont, LO[3].mont, LO[4].mont, LO[3].mont, LO[2].mont, LO[1].mont]
  assert Lmont == Lexpected

  Led = [EdPoint.from_mont(mont.scalarmult(s, L), s >= 4) for s in range(8)]
  assert Led == LO

  # Very special low order points
  assert mont.scalarmult(11, ZERO) == ZERO.mont
  assert mont.scalarmult(3, LO[4]) == LO[4].mont
  assert mont.scalarmult(4, LO[4]) == ZERO.mont

  # Any point times 8q should be point at infinity (ZERO)
  assert mont.scalarmult(4 * q, 2 * D) == ZERO.mont

  # Test v coordinate recovery
  assert mont.v(fe(9)) == fe(14781619447589544791020593568409986887264606134616475288964881837755586237401)

  with pytest.raises(ValueError) as exc:
    mont.v(fe(2))
  assert "not a valid point" in str(exc.value)

  with pytest.raises(ValueError) as exc:
    mont.v(ZERO.mont)
  assert "point at infinity" in str(exc.value)


def test_hashmap():
  # Just hitting the __hash__ functions
  assert len({fe(i * p) for i in range(2)}) == 1
  assert len({i * L for i in range(10)}) == 8

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
  assert repr(LO[0]) == "ZERO"
  assert repr(LO[1]) == "L"
  assert repr(LO[2]) == "LO[2]"
  for i, P in enumerate(LO):
    assert 8 * P == ZERO
    assert P.is_low_order
    assert not P.is_prime_group
    assert P.subgroup == i

    s = secret_scalar(token_bytes(32))
    Q = s * G + P
    assert not Q.is_low_order
    assert Q.subgroup == i

  # Dirty point generation
  s = toint(token_bytes(32)) % (8 * q)
  P = s * G
  Q = s * D
  assert Q.subgroup == s % 8
  assert Q == P + LO[Q.subgroup]


def test_edpk_vs_sodium():
  edpk, edsk = sodium.crypto_sign_keypair()

  k = secret_scalar(edsk)
  K = k * G
  edpk2 = bytes(K)
  assert edpk2.hex() == edpk.hex()

def test_mont_vs_sodium():
  edpk, edsk = sodium.crypto_sign_keypair()
  sk = sodium.crypto_sign_ed25519_sk_to_curve25519(edsk)
  pk = sodium.crypto_sign_ed25519_pk_to_curve25519(edpk)  # Note: the sign is lost (high bit random)
  assert pk[31] & 0x80 == 0
  # Mont secret key is just the clamped scalar
  k = secret_scalar(edsk)
  assert tobytes(k).hex() == sk.hex()
  # Public key converted from edsk
  K = k * G
  pkconv = K.montbytes  # sign always 0 to match sodium
  assert pk.hex() in pkconv.hex()
  # Public key converted from montpk
  K2 = EdPoint.from_montbytes(pk)
  pkconv2 = K2.montbytes_sign
  assert abs(K) == K2  # K2 from sodium is always positive
  assert pkconv2.hex() == pk.hex()


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
  # Valid signatures
  xed_verify(pk, msg1, sig1)
  xed_verify(pk, msg2, sig2)

  # Invalid signatures
  with pytest.raises(ValueError) as exc:
    xed_verify(pk, msg2, sig1)
  assert "Signature mismatch" == str(exc.value)

  with pytest.raises(ValueError) as exc:
    xed_verify(pk, msg1, sig2)
  assert "Signature mismatch" == str(exc.value)

  # Errors
  with pytest.raises(ValueError) as exc:
    xed_verify(pk, msg1, b"")
  assert "Invalid signature length" == str(exc.value)

  for P in LO[1:]:  # Test LO points noting that they cause different exceptions
    with pytest.raises(ValueError) as exc:
      xed_verify(P.montbytes_sign, msg1, sig1)
    assert "Invalid public key provided" == str(exc.value)

    with pytest.raises(ValueError) as exc:
      xed_verify(pk, msg1, P.montbytes_sign + sig1[32:])
    assert "Invalid R point on signature" == str(exc.value)

  with pytest.raises(ValueError) as exc:
    xed_verify(pk, msg1, sig1[:32] + tobytes(q))
  assert "Invalid s value on signature" == str(exc.value)

def test_elligator_highlevel():
  subgroups = set()

  for i in range(10):
    hidden, edsk = egcreate()
    assert eghide(edsk) == hidden

    # "curve25519 sk" conversion is really sha + clamp to get ed25519 scalar
    sk = sodium.crypto_sign_ed25519_sk_to_curve25519(edsk + bytes(32))  # + all zeroes bogus edpk
    edpk = sodium.crypto_scalarmult_ed25519_base(sk)  # ... so that we can calculate the edpk
    pk = sodium.crypto_sign_ed25519_pk_to_curve25519(edpk)

    # Can we restore the point?
    P = egreveal(hidden)  # restored dirty point
    P2 = secret_scalar(edsk) * G  # clean point from original secret
    assert P.undirty == P2

    # Convert the restored point to Ed/Mont
    edpk2 = bytes(P.undirty)
    pk2 = P.undirty.montbytes
    assert edpk2.hex() == edpk.hex()
    assert pk2.hex() == pk.hex()

    # Test ECDH protocol (using the dirty point)
    rpk, rsk = sodium.crypto_box_keypair()  # Recipient keypair
    shared1 = sodium.crypto_scalarmult(sk, rpk)
    shared2 = sodium.crypto_scalarmult(rsk, pk2)  # Using elligatored pk2
    assert shared1.hex() == shared2.hex()

    assert P.undirty == EdPoint.from_bytes(edpk)
    assert bytes(P.undirty).hex() == edpk.hex()

    # Keep track of the subgroups seen!
    subgroups.add(P.subgroup)
    if len(subgroups) > 2: break

  # Verify that we saw multiple subgroups
  assert len(subgroups) > 1, f"Should have found several but got {subgroups=}"

def test_non_elligator_key():
  with pytest.raises(ValueError) as exc:
    eghide(tobytes(5))  # edsk chosen by trial and error so that the pk is not good for elligator
  assert "The key cannot be Elligator hashed" == str(exc.value)
