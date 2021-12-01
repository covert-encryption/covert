import sys
from covert.__main__ import argparse
def test_argparse():
  sys.argv = "covert enc --recipient asdf -r asdf -Arrp recipient1".split()
  a = argparse()
  assert a.recipients == ['recipient1', 'recipient2']
  with pytest.raises(SystemExit):  # sys.exit() raises SystemExit exception which is received by pytest here
    a = argparse()

