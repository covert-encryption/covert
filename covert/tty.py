import io
import os
import sys
import time
from contextlib import contextmanager
from shutil import get_terminal_size


def editor():
  with fullscreen() as term:
    term.write(f'\x1B[1;1H\x1B[1;44m   〰 ENTER MESSAGE 〰   (ESC to finish)\x1B[0K\x1B[0m\n')
    data = ""
    startrow = row = col = 0
    while True:
      for key in term.reader():
        lines = data.split("\n") + [""]
        if key == 'ESC':
          return data
        elif key == 'BACKSPACE':
          if col > 0:
            col -= 1
            lines[row] = lines[row][:col] + lines[row][col + 1:]
          elif row > 0:
            row -= 1
            col = len(lines[row])
            lines[row] += lines[row + 1]
            del lines[row + 1]
        elif key == 'LEFT':
          if col > 0:
            col -= 1
          elif row > 0:
            row -= 1
            col = len(lines[row])
        elif key == 'RIGHT':
          if col < len(lines[row]):
            col += 1
          elif row < len(lines) - 1:
            row += 1
            col = 0
        elif key == 'UP' and row > 0:
          row -= 1
          col = min(col, len(lines[row]))
        elif key == 'DOWN' and row < len(lines) - 1:
          row += 1
          col = min(col, len(lines[row]))
        elif key == 'ENTER':
          lines.insert(row + 1, lines[row][col:])
          lines[row] = lines[row][:col]
          col = 0
          row += 1
        elif len(key) == 1:
          lines[row] = lines[row][:col] + key + lines[row][col:]
          col += 1
        if not lines[-1]:
          del lines[-1]
        data = "\n".join(lines)
      win = get_terminal_size()
      startrow = min(max(0, row - 1), startrow)
      startrow = max(row - win.lines + 2, startrow)
      draw = "\x1B[0K\n".join(l[:win.columns - 1] for l in data.split("\n")[startrow:startrow + win.lines - 1])
      term.write(f"\x1B[2;1H{draw}\x1B[0J\x1B[{row - startrow + 2};{col+1}H")


def read_hidden(prompt):
  with terminal() as term:
    term.write(f'{prompt}: \x1B[1;30m')
    try:
      data = ""
      t = time.monotonic()
      while True:
        for key in term.reader():
          if key == "ESC":
            raise KeyboardInterrupt
          elif key == "BACKSPACE":
            data = data[:-1]
          elif key == "ENTER":
            # Handle multi-line pastes
            if time.monotonic() - t > 0.2:
              return data
            data += '\n'
          elif len(key) == 1:
            data += key
          t = time.monotonic()
        status = f"  ({len(data)}) "
        term.write(f"{status}\x1B[{len(status)}D")
    finally:
      # Return to start of line and clear the prompt
      term.write(f"\x1B[0m\r\x1B[0K")


@contextmanager
def unix_terminal():
  fd = os.open('/dev/tty', os.O_RDWR | os.O_NOCTTY)
  with io.FileIO(fd, 'w+') as tty:
    old = termios.tcgetattr(fd)  # a copy to save
    new = old[:]
    new[3] &= ~termios.ECHO
    new[3] &= ~termios.ICANON
    tcsetattr_flags = termios.TCSAFLUSH
    if hasattr(termios, 'TCSASOFT'):
      tcsetattr_flags |= termios.TCSASOFT
    try:
      termios.tcsetattr(fd, tcsetattr_flags, new)
      yield Terminal(tty)
      # Try to prevent multi-line pastes flooding elsewhere
      time.sleep(0.1)
      termios.tcflush(fd, termios.TCIFLUSH)
    finally:
      # Restore the original state
      termios.tcsetattr(fd, tcsetattr_flags, old)
      tty.flush()


@contextmanager
def windows_terminal():
  yield Terminal(None)


@contextmanager
def stdio_terminal():
  raise NotImplementedError


try:
  import termios
  terminal = unix_terminal
except (ImportError, AttributeError):
  try:
    import msvcrt
    terminal = windows_terminal
  except ImportError:
    terminal = stdio_terminal


@contextmanager
def modeswitch(term):
  term.write('\x1B[?1049h\x1B[2J')
  try:
    yield
  finally:
    term.write('\x1B[2J\x1B[?1049l')


@contextmanager
def fullscreen():
  with terminal() as term, modeswitch(term):
    yield term


class Terminal:

  def __init__(self, tty=None):
    self.esc = ''
    self.tty = tty
    self.reader = self.reader_windows if tty is None else self.reader_unix

  def write(self, text):
    if self.tty:
      self.tty.write(text.encode())
      self.tty.flush()
    else:
      text = text.replace('\n', '\r\n')
      sys.stderr.write(text)
      #for ch in text:
      #  msvcrt.putwch(ch)

  def reader_windows(self):
    while True:
      ch = msvcrt.getwch()
      if ch == '\x00' or ch == 'à':
        ch = msvcrt.getwch()
        if ch == 'H': yield 'UP'
        elif ch == 'P': yield 'DOWN'
        elif ch == 'K': yield 'LEFT'
        elif ch == 'M': yield 'RIGHT'
        elif ch == 'G': yield 'HOME'
        elif ch == 'O': yield 'END'
        elif ch == 'S': yield 'DEL'
        #else: yield ch
      elif ch == '\x03':
        raise KeyboardInterrupt
      elif ch == '\x1B':
        yield 'ESC'
      elif ch == '\b':
        yield 'BACKSPACE'
      elif ch == '\t':
        yield 'TAB'
      elif ch == '\r':
        yield 'ENTER'
      elif ch.isprintable():
        yield ch
      if not msvcrt.kbhit():
        break

  def reader_unix(self):
    while True:
      # FIXME: UTF-8 streaming
      for ch in self.tty.read(16384).decode():
        if self.esc:
          self.esc += ch
          if self.esc in ("\x1B[", "\x1B[3"): continue
          elif self.esc == '\x1B\x1B': yield "ESC"
          elif self.esc == "\x1B[3~": yield 'DEL'
          elif len(self.esc) == 3:
            if ch == 'A': yield 'UP'
            elif ch == 'B': yield 'DOWN'
            elif ch == 'C': yield 'RIGHT'
            elif ch == 'D': yield 'LEFT'
            elif ch == 'H': yield 'HOME'
            elif ch == 'F': yield 'END'
          else:
            yield repr(self.esc)
          self.esc = ''
        elif ch == "\x1B":
          self.esc = ch
        elif ch == "\x01":
          yield 'HOME'
        elif ch == "\x05":
          yield 'END'
        elif ch == '\t':
          yield 'TAB'
        elif ch == '\x7F':
          yield 'BACKSPACE'
        elif ch == '\n':
          yield 'ENTER'
        elif ch.isprintable():
          yield ch
      if not self.esc:
        break
