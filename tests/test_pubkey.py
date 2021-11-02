from hashlib import sha512
from secrets import token_bytes

import nacl.bindings as sodium

from covert import sign
from covert.pubkey import (
  decode_age_pk, decode_age_sk, decode_pk, decode_sk, derive_symkey, encode_age_pk, encode_age_sk, sk_to_pk
)

# Test vectors from https://age-encryption.org/v1
AGE_PK = "age1zvkyg2lqzraa2lnjvqej32nkuu0ues2s82hzrye869xeexvn73equnujwj"
AGE_SK = "AGE-SECRET-KEY-1GFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPQ4EGAEX"
AGE_SK_BYTES = 32 * b"\x42"

# Create identity keypairs for Alice and Bob
ALICE_PK, ALICE_SK = sodium.crypto_kx_keypair()
BOB_PK, BOB_SK = sodium.crypto_kx_keypair()


def test_age_key_decoding():
  pk = decode_pk(AGE_PK)
  sk = decode_sk(AGE_SK)
  assert isinstance(pk, bytes)
  assert isinstance(sk, bytes)
  assert len(pk) == 32
  assert len(sk) == 32
  assert sk.hex() == AGE_SK_BYTES.hex()
  derived_pk = sk_to_pk(sk)
  assert derived_pk == pk


def test_age_key_encoding():
  assert decode_age_pk(AGE_PK) == decode_pk(AGE_PK)
  assert decode_age_sk(AGE_SK) == decode_sk(AGE_SK)
  assert encode_age_pk(decode_pk(AGE_PK)) == AGE_PK
  assert encode_age_sk(decode_sk(AGE_SK)) == AGE_SK


def test_ssh_key_decoding():
  pk = decode_pk("keys/ssh_ed25519.pub")
  sk = decode_sk("keys/ssh_ed25519")
  assert pk == sk_to_pk(sk)


def test_key_exchange():
  # Alice sends a message to Bob
  nonce = token_bytes(12)
  eph_pk, eph_sk = sodium.crypto_kx_keypair()
  assert len(eph_pk) == 32
  assert len(eph_sk) == 32
  alice_key = derive_symkey(nonce, eph_sk, BOB_PK)
  # Bob receives the message (including nonce and eph_pk)
  bob_key = derive_symkey(nonce, BOB_SK, eph_pk)
  assert alice_key == bob_key


from covert import sign


def test_inversion():
  x = int.from_bytes(token_bytes(32), "little")
  y = sign.modp_inv(x)
  z = (x*y) % sign.p
  assert z == 1


def test_signing():
  for i in range(100):
    presk = token_bytes(32)
    pk, sk = sodium.crypto_box_seed_keypair(presk)
    sk = sk[:32]
    assert sk.hex() == sha512(presk).digest()[:32].hex()
    assert len(pk) == 32
    edpk, edsk = sign.calculate_key_pair(presk)
    edpk2 = sign.convert_mont(pk)
    try:
      sodium.crypto_sign_open(sodium.crypto_sign(b'', presk + edpk), edpk2)
    except Exception:
      # We got the sign flip the wrong way. No worries, just flip it!
      edpk2 = (int.from_bytes(edpk2, 'little') ^ (1 << 255)).to_bytes(32, 'little')
      sodium.crypto_sign_open(sodium.crypto_sign(b'', presk + edpk), edpk2)
    assert edpk.hex() == edpk2.hex()
    pk2 = sodium.crypto_sign_ed25519_pk_to_curve25519(edpk)
    assert pk2.hex() == pk.hex()
    sk2 = sodium.crypto_sign_ed25519_sk_to_curve25519(presk + edpk)
    assert sk2.hex() == sign.clamp(sk).hex()


def test_signature_high_level():
  for i in range(100):
    presk = token_bytes(32)
    pk, sk = sodium.crypto_box_seed_keypair(presk)
    sk = sk[:32]
    blkhash = token_bytes(64)
    # Sign & verify
    signature = sign.signature(presk, blkhash)
    msg = sign.verify(pk, blkhash, signature)
    assert msg == blkhash
