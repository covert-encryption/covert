class AuthenticationError(ValueError):
  """Wrong key"""

class MalformedKeyError(ValueError):
  """Key string is malformed"""

class DecryptError(ValueError):
  """Decryption failed"""

class CliArgError(ValueError):
  """Invalid CLI argument"""
