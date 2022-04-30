class AuthenticationError(ValueError):
  """Authentication needed but not provided or is invalid"""

class MalformedKeyError(AuthenticationError):
  """Key string is malformed or keyfile is unsupported/corrupt"""

class DecryptError(ValueError):
  """Decryption failed"""

class CliArgError(ValueError):
  """Invalid CLI argument"""
