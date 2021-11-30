def test_argparser():
    sys.argv = "covert enc --recipient asdf -r asdf -Arrp recipient1".split()
    a = argparser()
    assert a.recipients == ['recipient1', 'recipient2']