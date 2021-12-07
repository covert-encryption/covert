import pytest

from covert import passphrase, util
from covert.wordlist import words


def test_no_shared_prefixes():
  w = list(sorted(words))
  for i in range(len(w) - 1):
    w1, w2 = w[i + 1], w[i]
    assert not w1.startswith(w2), f"{w1!r} starts with {w2!r}"


def test_generate():
  pw1 = passphrase.generate()
  pw2 = passphrase.generate()
  assert pw1 != pw2
  assert passphrase.generate(8, "-").count('-') == 7
  # This should randomly hit the regeneration because of weak password
  for i in range(10):
    passphrase.generate(1)
    passphrase.generate(2)
    passphrase.generate(3)


def test_costfactor():
  assert passphrase.costfactor(b"xxxxxxxx") == 16
  assert passphrase.costfactor(b"xxxxxxxxA") == 8
  assert passphrase.costfactor(b"xxxxxxxxAA") == 4
  assert passphrase.costfactor(b"xxxxxxxxAAA") == 2
  assert passphrase.costfactor(b"xxxxxxxxAAAA") == 1
  assert passphrase.costfactor(b"xxxxxxxxAAAAA") == 1


def test_pwhash_and_authkey():
  with pytest.raises(ValueError):
    passphrase.pwhash(b"short")

  pwh = passphrase.pwhash(b"xxxxxxxxAAAA")
  assert len(pwh) == 16
  assert pwh.hex() == "dbc27f84f3f3747826801c68e3e8aa1b"  # Calculated in browser

  authkey = passphrase.authkey(pwh, b"faketestsalt")
  assert len(authkey) == 32
  assert authkey.hex() == "a8586c8811ab565a2f30ad876305ebecfc93a3302dd3a3ba2ac83c07a961b9c8"

  with pytest.raises(Exception) as e:
    passphrase.authkey(bytes(16), bytes(16))
  assert "Invalid arguments pwhash" in str(e.value)

  with pytest.raises(Exception) as e:
    passphrase.authkey(bytes(12), bytes(12))
  assert "Invalid arguments pwhash" in str(e.value)

def test_autocomplete():
  assert passphrase.autocomplete("", 0) == ("", 0, "enter a few letters of a word first")
  assert passphrase.autocomplete("peaceangle", 5) == ("peaceangle", 5, "enter a few letters of a word first")
  assert passphrase.autocomplete("ang", 3) == ("angle", 5, "")
  assert passphrase.autocomplete("peaangle", 3) == ("peaceangle", 5, "")
  assert passphrase.autocomplete("peaceangleol", 12) == ("peaceangleol", 12, "…d …ive")
  assert passphrase.autocomplete("peaceangleoli", 13) == ("peaceangleolive", 15, "")
  assert passphrase.autocomplete("peacexxx", 8) == ("peacexxx", 8, "no matches")
  assert passphrase.autocomplete("a", 1) == ("a", 1, "too many matches")


def test_pwhints():
  out, valid = passphrase.pwhints("")
  assert not valid
  assert "Choose a passphrase you don't use elsewhere." in out

  out, valid = passphrase.pwhints("abcabcabcabc")
  assert not valid
  assert 'Repeats like "abcabcabc" are only slightly harder to guess than "abc".' in out

  out, valid = passphrase.pwhints("ridiculouslylongpasswordthatwecannotletzxcvbncheckbecauseitbecomestooslow")
  assert valid
  assert 'centuries' in out
  assert 'Seems long enough' in out

  out, valid = passphrase.pwhints("quitelegitlongpwd")
  assert valid
  assert 'fastest hashing' in out

  out, valid = passphrase.pwhints("faketest")
  assert valid
  assert '16 times faster' in out


def test_normalization():
  """Unicode may be written in many ways that must lead to the same password"""
  win = '\uFEFF\u1E69'  # BOM + composed (NFC)
  mac = '\u0073\u0323\u0307'  # Decomposed (NFD)
  src = 'ṩ'  # Different order decomposed (and possibly mutated in transit of source code)
  assert win != mac
  assert mac != src
  assert src != win

  assert util.encode(win) == b'\xe1\xb9\xa9'
  assert util.encode(mac) == b'\xe1\xb9\xa9'
  assert util.encode(src) == b'\xe1\xb9\xa9'
