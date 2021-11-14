import os
import struct
from base64 import b64decode
from contextlib import suppress
from urllib.parse import quote
from urllib.request import urlopen

import nacl.bindings as sodium
from pysodium import crypto_pwhash_scryptsalsa208sha256

from covert import bech, passphrase, util


def derive_symkey(nonce, local, remote):
  assert local.sk, f"Missing secret key for {local=}"
  shared = sodium.crypto_scalarmult(local.sk, remote.pk)
  return sodium.crypto_hash_sha512(bytes(nonce) + shared)[:32]


class Key:

  def __init__(self, *, keystr="", comment="", sk=None, pk=None, edsk=None, edpk=None):
    self.sk = self.pk = self.edsk = self.edpk = None
    self.keystr = keystr
    self.comment = comment
    # Create if no parameters were given
    if not (sk or pk or edsk or edpk):
      edpk, edsk = sodium.crypto_sign_keypair()
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
      assert not self.pk or self.pk == pk_conv
      self.pk = pk_conv
    if self.edsk:
      edsk_hashed = self.sk
      edpk_conv = sodium.crypto_scalarmult_ed25519_base(edsk_hashed)
      assert not self.edpk or self.edpk == edpk_conv
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
    with urlopen(f"https://github.com/{quote(ghuser, safe='')}.keys") as resp:
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
  try:
    return decode_sk(keystr)
  except ValueError:
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
      data = b64decode("".join(lines[1:-1]), validate=True)
      keys = [decode_sk_ssh(data)]
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
  # Magic for MiniSign
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


def decode_sk_ssh(data):
  """Parse the Base64 decoded binary data within a secret key file."""
  # This needs cleanup, perhaps also a real parser instead of this hack,
  # and support for encrypted keyfiles
  magic = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00 "
  while magic in data:
    pos = data.find(magic) + len(magic)
    edpk = data[pos:pos + 32]
    pos2 = data.find(edpk + b"\x00\x00\x00@")
    if pos2 > 0:
      edpk2 = data[pos2:pos2 + 32]
      #cmtlen = int.from_bytes(data[pos2 + 36 + 64:pos2 + 36 + 64 + 4], "big")
      #cmt = data[pos2 + 36 + 64 + 4:pos2 + 36 + 64 + 4 + cmtlen].decode()
      #pkhash = b64encode(data[pos - len(magic):pos + 32]).decode()
      if edpk2 == edpk:
        edsk = data[pos2 + 36:pos2 + 36 + 64]
        return Key(edsk=edsk, edpk=edpk)
    data = data[pos + len(magic):]
  raise ValueError("No ssh-ed25519 keys could be read (password protection is not supported)")


def decode_sk_minisign(keystr):
  data = b64decode(keystr)
  fmt, salt, ops, mem, token = struct.unpack('<6s32sQQ104s', data)
  if fmt != b'EdScB2':
    raise ValueError(f'Not a (supported) MiniSign secret key {fmt=}')
  pw = util.encode(passphrase.ask('MiniSign passkey')[0])
  out = crypto_pwhash_scryptsalsa208sha256(104, pw, salt, ops, mem)
  token = util.xor(out, token)
  keyid = token[:8]
  edsk = token[8:40]
  edpk = token[40:72]
  csum = token[72:]
  b2state = sodium.crypto_generichash_blake2b_init()
  sodium.crypto_generichash.generichash_blake2b_update(b2state, fmt[:2] + keyid + edsk + edpk)
  csum2 = sodium.crypto_generichash.generichash_blake2b_final(b2state)
  if csum != csum2:
    raise ValueError('Unable to decrypt MiniSign secret key')
  return Key(edsk=edsk, edpk=edpk)


def decode_age_pk(keystr):
  return Key(keystr=keystr, comment="age", pk=bech.decode("age", keystr.lower()))


def encode_age_pk(key):
  return bech.encode("age", key.pk)


def decode_age_sk(keystr):
  return Key(keystr=keystr, comment="age", sk=bech.decode("age-secret-key-", keystr.lower()))


def encode_age_sk(key):
  return bech.encode("age-secret-key-", key.sk).upper()
