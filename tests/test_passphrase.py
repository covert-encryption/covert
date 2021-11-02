from covert import passphrase
from covert.wordlist import words


def test_no_shared_prefixes():
  w = list(sorted(words))
  for i in range(len(w) - 1):
    w1, w2 = w[i + 1], w[i]
    assert not w1.startswith(w2), f"{w1!r} starts with {w2!r}"
