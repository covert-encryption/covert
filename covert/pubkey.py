import os
import struct
from base64 import b64decode
from contextlib import suppress
from urllib.parse import quote
from urllib.request import urlopen

import nacl.bindings as sodium

from covert import bech, elligator, passphrase, sshkey, util


def derive_symkey(nonce, local, remote):
  assert local.sk, f"Missing secret key for {local=}"
  shared = sodium.crypto_scalarmult(local.sk, remote.pk)
  return sodium.crypto_hash_sha512(bytes(nonce) + shared)[:32]


class Key:

  def __init__(self, *, keystr="", comment="", sk=None, pk=None, edsk=None, edpk=None, pkhash=None):
    self.sk = self.pk = self.edsk = self.edpk = None
    self.keystr = keystr
    self.comment = comment
    self.pkhash = pkhash
    anykey = sk or pk or edsk or edpk
    # Restore pk from hashed format
    if pkhash is not None:
      if anykey:
        raise ValueError("Invalid Key argument: pkhash cannot be combined with other keys")
      pk = elligator.unhash(pkhash)
    # Create elligator2-compatible keys if no parameters were given
    elif not anykey:
      while True:
        edpk, edsk = sodium.crypto_sign_keypair()
        pk = sodium.crypto_sign_ed25519_pk_to_curve25519(edpk)
        if elligator.ishashable(pk):
          break  # 50 % should succeed
      self.pkhash = elligator.keyhash(pk)
    # Store each parameter and convert ed25519 keys to curve25519
    if edsk:
      self.edsk = bytes(edsk[:32])
      # Note: Sodium edsk are actually edsk + edpk so we must add a bogus edpk
      self.sk = sodium.crypto_sign_ed25519_sk_to_curve25519(self.edsk + bytes(32))
    if edpk:
      self.edpk = bytes(edpk)
      try:
        self.pk = sodium.crypto_sign_ed25519_pk_to_curve25519(self.edpk)
      except RuntimeError:  # Unexpected library error from nacl.bindings
        raise ValueError("Invalid Ed25519 public key")
    if sk:
      sk = bytes(sk[:32])
      assert not edsk or self.sk == sk
      self.sk = sk
    if pk:
      pk = bytes(pk)
      assert not edpk or self.pk == pk
      self.pk = pk
    self._generate_public()
    self._validate()

  def __eq__(self, other):
    # If Curve25519 pk matches, everything else matches too
    return self.pk == other.pk

  def __hash__(self):
    return hash(self.pk)

  def __repr__(self):
    if self.edsk:
      t = 'EdSK'
    elif self.sk:
      t = 'SK'
    elif self.edpk:
      t = 'EdPK'
    else:
      t = 'PK'
    return f"Key[{self.pk.hex()[:8]}:{t}]"

  def __str__(self):
    """Pretty short string formatting for UI"""
    if len(self.comment) < 4:
      key = self.keystr or repr(self)
      key = f'{key} {self.comment}' if self.comment else key
    else:
      key = self.comment
    return f"…{key[-12:]}" if len(key) > 30 else key

  def _generate_public(self):
    """Convert secret keys to public"""
    if self.sk:
      pk_conv = sodium.crypto_scalarmult_base(self.sk)
      if self.pk and self.pk != pk_conv:
        raise ValueError("Secret and public key mismatch")
      self.pk = pk_conv
    if self.edsk:
      edsk_hashed = self.sk
      edpk_conv = sodium.crypto_scalarmult_ed25519_base(edsk_hashed)
      if self.edpk and self.edpk != edpk_conv:
        raise ValueError("Secret and public key mismatch")
      self.edpk = edpk_conv

  def _validate(self):
    """Test if the keypairs work correctly"""
    if self.edsk:
      signed = sodium.crypto_sign(b"Message", self.edsk + self.edpk)
      sodium.crypto_sign_open(signed, self.edpk)
    if self.sk:
      nonce = bytes(sodium.crypto_box_NONCEBYTES)
      ciphertext = sodium.crypto_box(b"Message", nonce, self.pk, self.sk)
      sodium.crypto_box_open(ciphertext, nonce, self.pk, self.sk)


def read_pk_file(keystr):
  ghuser = None
  if keystr.startswith("github:"):
    ghuser = keystr[7:]
    url = f"https://github.com/{quote(ghuser, safe='')}.keys"
    with urlopen(url) as resp:  # nosec
      data = resp.read()
  elif not os.path.isfile(keystr):
    raise ValueError("Keyfile {keystr} not found")
  else:
    with open(keystr, "rb") as f:
      data = f.read()
  if not data:
    raise ValueError(f'Nothing found in {keystr}')
  # A key token per line, except skip comments and empty lines
  lines = data.decode().rstrip().split("\n")
  keys = []
  for l in lines:
    with suppress(ValueError):
      keys.append(decode_pk(l))
  if not keys:
    raise ValueError(f'No public keys recognized from file {keystr}')
  for i, k in enumerate(keys, 1):
    if ghuser:
      k.comment = f"{ghuser}@github"
    k.keystr = f"{keystr}:{i}" if len(keys) > 1 else keystr
  return keys


def read_sk_any(keystr):
  with suppress(ValueError):
    return decode_sk(keystr)
  return read_sk_file(keystr)


def read_sk_file(keystr):
  if not os.path.isfile(keystr):
    raise ValueError(f"Secret key file {keystr} not found")
  with open(keystr, "rb") as f:
    try:
      lines = f.read().decode().replace('\r\n', '\n').rstrip().split('\n')
    except ValueError:
      raise ValueError(f"Keyfile {keystr} could not be decoded. Only UTF-8 text is supported.")
    if lines[0] == "-----BEGIN OPENSSH PRIVATE KEY-----":
      keys = sshkey.decode_sk("\n".join(lines))
    elif lines[1].startswith('RWRTY0Iy'):
      keys = [decode_sk_minisign(lines[1])]
    else:
      # A key token per line, except skip comments and empty lines
      keys = [
        decode_sk(l) for l in lines if l.strip() and not l.startswith('untrusted comment:') and not l.startswith('#')
      ]
  for i, k in enumerate(keys, 1):
    k.keystr = f"{keystr}:{i}" if len(keys) > 1 else keystr
  return keys


def decode_pk(keystr):
  # Age keys use Bech32 encoding
  if keystr.startswith("age1"):
    return decode_age_pk(keystr)
  # Try Base64 encoded formats
  try:
    token, comment = keystr, ''
    if keystr.startswith('ssh-ed25519 '):
      t, token, *comment = keystr.split(' ', 2)
      comment = comment[0] if comment else 'ssh'
    keybytes = b64decode(token, validate=True)
    ssh = keybytes.startswith(b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00 ")
    minisign = len(keybytes) == 42 and keybytes.startswith(b'Ed')
    if minisign:
      comment = 'ms'
    if ssh or minisign:
      return Key(keystr=keystr, comment=comment, edpk=keybytes[-32:])
    # WireGuard keys
    if len(keybytes) == 32:
      return Key(keystr=keystr, comment="wg", pk=keybytes)
  except ValueError:
    pass
  raise ValueError(f"Unrecognized key {keystr}")


def decode_sk(keystr):
  # Age secret keys in Bech32 encoding
  if keystr.lower().startswith("age-secret-key-"):
    return decode_age_sk(keystr)
  # Magic for Minisign
  if keystr.startswith('RWRTY0Iy'):
    return decode_sk_minisign(keystr)
  # Plain Curve25519 key (WireGuard)
  try:
    keybytes = b64decode(keystr, validate=True)
    if len(keybytes) == 32:
      return Key(sk=keybytes)
  except ValueError:
    pass
  raise ValueError(f"Unable to parse private key {keystr!r}")


def decode_sk_minisign(keystr, pw=None):
  # None means try without password, then ask
  if pw is None:
    try:
      return decode_sk_minisign(keystr, b'')
    except ValueError:
      pass
    pw = util.encode(passphrase.ask('Minisign passkey')[0])
    return decode_sk_minisign(keystr, pw)
  data = b64decode(keystr)
  fmt, salt, ops, mem, token = struct.unpack('<6s32sQQ104s', data)
  if fmt != b'EdScB2' or ops != 1 << 25 or mem != 1 << 30:
    raise ValueError(f'Not a (supported) Minisign secret key {fmt=}')
  out = sodium.crypto_pwhash_scryptsalsa208sha256_ll(pw, salt, n=1 << 20, r=8, p=1, maxmem=float('inf'), dklen=104)
  token = util.xor(out, token)
  keyid, edsk, edpk, csum = struct.unpack('8s32s32s32s', token)
  b2state = sodium.crypto_generichash_blake2b_init()
  sodium.crypto_generichash.generichash_blake2b_update(b2state, fmt[:2] + keyid + edsk + edpk)
  csum2 = sodium.crypto_generichash.generichash_blake2b_final(b2state)
  if csum != csum2:
    raise ValueError('Unable to decrypt Minisign secret key')
  return Key(edsk=edsk, edpk=edpk)


def decode_age_pk(keystr):
  return Key(keystr=keystr, comment="age", pk=bech.decode("age", keystr.lower()))


def encode_age_pk(key):
  return bech.encode("age", key.pk)


def decode_age_sk(keystr):
  return Key(keystr=keystr, comment="age", sk=bech.decode("age-secret-key-", keystr.lower()))


def encode_age_sk(key):
  return bech.encode("age-secret-key-", key.sk).upper()
