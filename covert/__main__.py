from sys import argv, exit, stderr, stdout

import covert
from covert.cli import main_benchmark, main_dec, main_enc

cmdhelp = f"""\
Covert {covert.__version__} - A file and message encryptor with strong anonymity
 💣  Things encrypted with this developer preview mayn't be readable evermore

Usage:
  covert enc [-p | -r PUBKEY | -R KEYFILE]... [-o OUTPUT] [FILE | DIR]...
  covert dec [-i PRIVKEY]... [INPUT] [-o OUTPUT]
  covert benchmark

Note: covert enc/dec with no other arguments will use the console.

Encryption options:
  -p, --passphrase  Ask for passphrase (default if no other recipients)
  -r --recipient K  Encrypt to the specified public key: RW…, AAAA…, age1…
  -R, --keyfile FN  Read recipients from a local keyfile, or:
                      github:foo - Download foo's SSH keys from Github
  --wide-open       No authentication required, anyone can open the file

  -i --identity FN  Sign the message using secret keys (file or key)
  -o --output FN    Encrypted file to output (binary unless -a is used)
  -a --armor        Encode to Base64 format (default if output is console)
  --pad PERCENT     Random padding preferred amount (0 disable, 5 default)

Filenames or folders given are added to the archive, omitting full paths.
A message with file attachments can be written by adding a hyphen '-'.

Decryption options:
  -o --output PATH  A folder/ to extract files or a file for message output
  -i --identity FN  Use the given keyfile or secret key instead of password

Example:
  $ minisign -G -p foo.pub -s foo.key
  $ covert enc -R foo.pub - pictures/ -o unsuspicious.dat
  $ covert dec -i foo.key unsuspicious.dat -o new_pictures/
"""


class Args:

  def __init__(self):
    self.files = []
    self.askpass = None
    self.authpw = []
    self.authpk = []
    self.authfile = []
    self.outfile = []
    self.identity = []
    self.padding = "5"
    self.noauth = None
    self.armor = None


encargs = dict(
  askpass='-p --passphrase'.split(),
  authpw='--password'.split(),
  noauth='--wide-open'.split(),
  authpk='-r --recipient'.split(),
  authfile='-R --keyfile --recipients-file'.split(),
  identity='-i --identity'.split(),
  outfile='-o --out --output'.split(),
  armor='-a --armor'.split(),
  padding='--pad --padding'.split(),
)

decargs = dict(
  identity='-i --identity'.split(),
  outfile='-o --out --output'.split(),
)


def argparse():
  # Custom parsing due to argparse module's limitations
  av = argv[1:]
  if not av or any(a.lower() in ('-h', '--help') for a in av):
    first, rest = cmdhelp.rstrip().split('\n', 1)
    if stdout.isatty():
      print(f'\x1B[1;44m{first:78}\x1B[0m\n{rest}')
    else:
      print(f'{first}\n{rest}')
    exit(0)
  if any(a.lower() in ('-v', '--version') for a in av):
    print(cmdhelp.split('\n')[0])
    exit(0)
  ad = {}
  args = Args()
  # Support a few other forms for Age etc. compatibility (but only as the first arg)
  if av[0].lower() in ('enc', 'encrypt', '-e', '--encrypt'):
    args.mode = 'enc'
    ad = encargs
  elif av[0].lower() in ('dec', 'decrypt', '-d', '--decrypt'):
    args.mode = 'dec'
    ad = decargs
  elif av[0].lower() in ('bench', 'benchmark'):
    args.mode = 'benchmark'
  elif next((k for k, v in encargs.items() if av[0] in v), None) is not None:
    args.mode = 'enc'
    ad = encargs
    av.insert(0, None)
  else:
    stderr.write(' 💣  Invalid or missing command (enc/dec/benchmark).\n')
    exit(1)

  aiter = iter(av[1:])
  for a in aiter:
    if not a.startswith('-'):
      args.files.append(a)
      continue
    if a == '-':
      args.files.append(True)
      continue
    if a == '--':
      args.files += args
      break
    if not a.startswith('--') and len(a) > 2:
      stderr.write(f' 💣  Short arguments cannot be combined: covert {args.mode} {a}\n')
      exit(1)
    if a.startswith('--'):
      a = a.lower()
    argvar = next((k for k, v in ad.items() if a in v), None)
    if argvar is None:
      stderr.write(f' 💣  Unknown argument: covert {args.mode} {a}\n')
      exit(1)
    try:
      var = getattr(args, argvar)
      if isinstance(var, list):
        var.append(next(aiter))
      elif isinstance(var, str):
        setattr(args, argvar, next(aiter))
      else:
        setattr(args, argvar, True)
    except StopIteration:
      stderr.write(f' 💣  Argument parameter missing: covert {args.mode} {a} …\n')
      exit(1)

  return args


def main():
  args = argparse()
  if len(args.outfile) > 1:
    raise ValueError('Only one output file may be specified')
  args.outfile = args.outfile[0] if args.outfile else None
  # Authentication methods
  if not (args.authpw or args.authpk or args.noauth or args.identity):
    args.authpw = [True]
  if args.noauth:
    if args.authpw or args.authpk:
      raise ValueError("--wide-open cannot be used with other authentication methods")

  try:
    if args.mode == "enc":
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
