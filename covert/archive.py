import os
import random
from enum import IntEnum
from glob import glob
from io import BytesIO

import msgpack

from covert import util

assert msgpack.version >= (1, 0, 0), 'Old 0.5.6 version creates invalid archives.'


class Stage(IntEnum):
  INDEX = 0
  FILE = 1
  FILE_STREAM = 2
  FINALIZE = 3
  END = 4


class Archive:

  def __init__(self):
    self.stage = Stage.INDEX
    self.extrasize = 0
    self.pos = 0
    self.index = {}
    self.format = None
    self.prevfile = None
    self.flist = []
    self.fidx = None
    self.fpos = None
    self.padding = 0
    self.buffer = bytes()
    self.nextfilecb = None

  @property
  def file(self):
    return self.fds[self.fidx]

  @property
  def curfile(self):
    return None if self.fidx is None else self.flist[self.fidx]

  @property
  def bytesleft(self):
    return None if self.fidx is None else self.flist[self.fidx]['s'] - self.fpos

  def nextfile(self):
    assert not self.bytesleft
    self.prevfile = self.curfile
    if self.stage in (Stage.FILE, Stage.FILE_STREAM):
      prev = self.curfile
      if prev['s'] != self.fpos:
        raise Exception(f'Archive.nextfile called with {self.curfile=} at {self.fpos=}')
      self.fidx += 1
    elif self.stage is Stage.INDEX:
      self.fidx = 0
    self.fpos = 0
    if self.fidx == len(self.flist):
      self.stage = Stage.FINALIZE
      self.fidx = None
      if self.nextfilecb:
        self.nextfilecb(self.prevfile, self.curfile)
      return False
    if self.curfile.get('s') is None:
      self.stage = Stage.FILE_STREAM
      self.curfile['s'] = 0
    else:
      self.stage = Stage.FILE
    if self.nextfilecb:
      self.nextfilecb(self.prevfile, self.curfile)
    return True

  def encodeindex(self):
    """Choose format and return index bytes."""
    if not self.format and len(self.flist) == 1 and list(self.flist[0].keys()) == ['s']:
      # Now we can and want to use the short format
      self.format = 0
      return msgpack.packb(self.index['f'][0]['s'])
    self.format = 1
    return msgpack.packb(self.index)

  def encode(self, block):
    """Encode archive into blocks."""
    while block.spaceleft and (self.stage is not Stage.END or self.buffer):
      # Flush out any buffered data
      if self.buffer:
        self.buffer = block.consume(self.buffer)
        continue
      # Fast path for files where the size is known
      if self.stage == Stage.FILE:
        if not self.bytesleft:
          self.nextfile()
          continue
        num = self.file.readinto(block.data[block.pos:block.pos + self.bytesleft])
        if not num:
          raise ValueError(f"Unexpected end of file {self.curfile.get('n', self.curfile)} at {self.file.tell():,} bytes (was {self.curfile.get('s'):,} bytes)")
        block.pos += num
        self.fpos += num
        continue
      # Msgpack structures and streaming use slower buffering for simplicity
      if self.stage == Stage.INDEX:
        # Write index
        self.buffer = self.encodeindex()
        self.nextfile()
      elif self.stage == Stage.FILE_STREAM:
        # Implement non-realtime streaming (input from pipe)
        assert not self.buffer
        maxdata = 10 << 20
        buffer = memoryview(bytearray(5 + maxdata))
        n = self.file.readinto(buffer[5:])
        self.fpos += n
        enclen = msgpack.packb(n)
        if len(enclen) == 5 and n == maxdata:
          buffer[:5] = enclen
        elif n == 0:
          buffer = enclen
          self.curfile['s'] = self.fpos
          self.nextfile()
        else:
          # Reformat buffer (rare so performance is no issue)
          buffer = enclen + buffer[5:5 + n]
        self.buffer = buffer
      elif self.stage == Stage.FINALIZE:
        self.buffer += self.padding * msgpack.packb(None)
        self.stage = Stage.END
      else:
        raise Exception(f'Should not end up here, Archive bug {self.stage=}')

  @property
  def total_size(self):
    # A simple calculation, streaming files are at most partially included (extrasize)
    return sum(f['s'] if 's' in f else 0 for f in self.flist) + self.extrasize

  def random_padding(self, p=0.05):
    """Randomize the amount of padding. Can be called after adding files but before encoding."""
    assert self.stage <= Stage.FINALIZE
    self.padding = util.random_padding(self.total_size, p)

  def decode(self, blocks):
    it = iter(blocks)
    try:
      block = next(it)
      while self.stage is not Stage.END:
        # Fast path for file data
        if databytes := self.bytesleft:
          if not block:
            block = next(it)
          b, block = block[:databytes], block[databytes:]
          self.pos += len(b)
          self.fpos += len(b)
          yield b
          continue
        if self.stage == Stage.FILE:
          yield self.nextfile()
          continue
        # Read a MsgPack object
        try:
          unp = msgpack.Unpacker(BytesIO(block))
          val = unp.unpack()
          self.pos += unp.tell()
          block = block[unp.tell():]
        except ValueError:
          raise ValueError(f'Corrupt MsgPack data in archive. {self.curfile=}')
        except msgpack.OutOfData:
          if len(block) > (1 << 20):
            raise ValueError(f"Extremely large msgpack object. This is either corruption or a malformatted archive.")
          block = bytes(block) + bytes(next(it))
          continue
        # MsgPack parsing
        if val is None:
          # Padding allowed and ignored at any stage
          self.padding += 1
          # Fast skip of bulk padding
          more = bytes(block).count(b'\xC0')
          if more == len(block):
            self.pos += more
            self.padding += more
            block = b''
        elif self.stage == Stage.INDEX:
          self.decodeindex(val)
          yield self.index
          yield self.nextfile()
        elif self.stage == Stage.FILE_STREAM:
          # Chunk size is expected while streaming a file
          if not isinstance(val, int) or val < 0:
            raise ValueError(f'Archive corrupted: expected file chunk size, got something else.')
          if val:
            self.curfile['s'] = self.curfile.get('s', 0) + val
          else:
            yield self.nextfile()
        else:
          raise ValueError(
            f"Invalid or corrupted data structures found within archive.\n{self.index=}\n{self.stage} {self.pos=} {val=} @ {bytes(block[:16]).hex()}"
          )
    except StopIteration:
      if self.stage is Stage.FINALIZE:
        self.stage = Stage.END
        return
      raise ValueError(f'Unexpected end of archive data, {self.stage=} {self.curfile=}')

  def decodeindex(self, index):
    # Convert short format to advanced format
    if isinstance(index, int):
      index = dict(f=[dict(s=index)])
    if not isinstance(index, dict):
      raise ValueError('Archive index not found.')
    self.index = index
    if 'f' in index:
      self.flist = index['f']
      # Basic validation
      for f in self.flist:
        if 's' in f:
          if not isinstance(f['s'], int) or f['s'] < 0:
            raise ValueError('Invalid or corrupted archive, found negative file size.')
        if 'n' in f:
          n = f['n']
          if not isinstance(n, str) or not 0 < len(n.encode()) < 256:
            raise ValueError('Invalid filename or corruption of archive.')
          if not n.isprintable() or any(c in R'\:' for c in n) or n[0] == '/':
            raise ValueError(f'Invalid filename {n}')

  def file_index(self, files):
    self.fds = []
    self.flist = []
    for f in files:
      if isinstance(f, str):
        name = f.replace("\\", "/")
        if '*' in name or '?' in name:
          files2 = glob(f, recursive=True)
        elif name.endswith("/") or os.path.isdir(f):
          files2 = glob(os.path.join(f, '**'), recursive=True)
        else:
          files2 = [f]
        skip = len(os.path.join(name, "").replace("\\", "/").split("/")) - 2
        for f in files2:
          if os.path.isdir(f):
            continue
          if not os.path.isfile(f):
            raise ValueError(f"File {f!r} not found")
          p = []
          skipfile = False
          for d in f.replace("\\", "/").split("/")[skip:]:
            if d in ('.', '..'):
              p = []
              continue
            p.append(d)
          else:
            name = "/".join(p)
            size = os.path.getsize(f)
            self.flist.append(dict(n=name, s=size))
            self.fds.append(open(f, "rb"))
      elif isinstance(f, bytes):
        self.flist.append(dict(s=len(f)))
        self.fds.append(BytesIO(f))
      else:
        data = f.read(10 << 20)
        n = None
        d = dict()
        if len(data) > 1e5:
          d['n'] = 'noname.txt'
        try:
          data.decode()
        except UnicodeDecodeError:
          d['n'] = 'noname.dat'
        if len(data) == 10 << 20:
          # Getting too much data to buffer all, needs streaming
          self.extrasize += len(data)
          self.fds.append(CombinedIO(data, f))
        else:
          d['s'] = len(data)
          self.fds.append(BytesIO(data))
        self.flist.append(d)
    if self.flist:
      self.index['f'] = self.flist


class CombinedIO:
  """Streaming input that returns from a pre-read buffer and then from the file."""

  def __init__(self, buffer, file):
    self.buffer = buffer
    self.file = file

  def read1(self, maxsize):
    if self.buffer:
      if len(self.buffer) >= maxsize:
        ret = self.buffer[:maxsize]
        self.buffer = self.buffer[maxsize:]
      else:
        ret = self.buffer + self.file.read1(maxsize - len(self.buffer))
        self.buffer = None
      return ret
    return self.file.read1(maxsize)

  def readinto(self, outbuf):
    if self.buffer:
      maxsize = len(outbuf)
      if len(self.buffer) >= maxsize:
        outbuf[:] = self.buffer[:maxsize]
        self.buffer = self.buffer[maxsize:]
        return maxsize
      l = len(self.buffer)
      outbuf[:l] = self.buffer
      self.buffer = None
      return l + self.file.readinto(outbuf[l:])
    return self.file.readinto(outbuf)
