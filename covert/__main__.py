import argparse
from sys import stderr

from covert.cli import main_benchmark, main_dec, main_enc


def main():
  parser = argparse.ArgumentParser(
    description="Strong encryption and decryption. Authentication arguments may be combined and repeated to use multiple alternative methods."
  )
  parser_main = parser.add_argument_group("Common options")
  parser_main.add_argument("mode", choices=["enc", "dec", "benchmark"], help="encryption or decryption mode")
  parser_enc = parser.add_argument_group("Encryption only")
  parser_dec = parser.add_argument_group("Decryption only")
  parser_main.add_argument("files", type=str, nargs="*", help="files to encrypt or decrypt (default: read from stdin)")
  parser_main.add_argument("-o", "--out", dest="outfile", metavar="FILE", help="output file (default stdout)")
  parser_main.add_argument(
    "-p", "--passphrase", dest="authpw", action="append_const", const=True, help="ask for password"
  )
  parser_main.add_argument(
    "--password", dest="authpw", metavar="PWD", action="append", help="password from command line (insecure)"
  )
  parser_enc.add_argument(
    "-r",
    "--recipient",
    dest="authpk",
    metavar="PUBKEY",
    action="append",
    help="encrypt for the given ED25519 public key or file:\n"
    "  age1zvky... (age public key)\n"
    "  AAAAC3Nz... (ssh-ed25519)\n"
    "  ~/.ssh/id_ed25519.pub  (to yourself)\n"
    "  github:username  (ssh key of any Github user)",
  )
  parser_dec.add_argument(
    "-I",
    "--identity",
    dest="identity",
    metavar="key",
    action="append",
    help="sign or decrypt with the given ED25519 private key file"
  )
  parser_enc.add_argument(
    "--padding", metavar='%', help="preferred random padding percentage (0 to disable, default 5)"
  )
  parser_enc.add_argument(
    "--wide-open", dest="noauth", action="store_true", help="allow anyone to open the file, no password needed"
  )
  parser_main.add_argument(
    "-a", "--armor", dest="armor", action="store_true", help="ciphertext that can be copy&pasted"
  )

  args = parser.parse_args()

  if not args.authpw:
    args.authpw = []
  if not args.authpk:
    args.authpk = []
  if not args.identity:
    args.identity = []

  # Authentication methods
  if not (args.authpw or args.authpk or args.noauth or args.identity):
    args.authpw = [True]
  if args.noauth:
    if args.authpw or args.authpk:
      raise ValueError("--wide-open cannot be used with other authentication methods")

  try:
    if args.mode == "enc":
      stderr.write(" 💣  Things encrypted with this developer preview may not be readable ever again.\n")
      main_enc(args)
    elif args.mode == "dec":
      main_dec(args)
    elif args.mode == "benchmark":
      main_benchmark(args)
  except ValueError as e:
    stderr.write(f"Error: {e}\n")
  except BrokenPipeError:
    stderr.write('I/O error (broken pipe)\n')
  except KeyboardInterrupt:
    stderr.write("Interrupted.\n")


if __name__ == "__main__":
  main()
