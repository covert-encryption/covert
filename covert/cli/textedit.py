import os
from shutil import get_terminal_size
from typing import List


def word_wrap(lines: List):
  rtext = [""]
  dict = []
  curlength = maxi = 0
  MAX_CHARACTERS = os.get_terminal_size().columns
  for i, line in enumerate(lines):
    dict.insert(len(dict), i)
    if len(line) >= MAX_CHARACTERS:
      words = []
      start = 0

      # Wrap spaces correctly
      for id, c in enumerate(line):
        if not c.isspace():
          if len(line) > id + 1:
            if line[id + 1].isspace():

              # Do not count it as a separate word if there is more than 1 space in a row (usually happens in code)
              # Fixes a bug with an unneeded line being inserted sometimes
              if len(line) > id + 2 and line[id + 2].isspace():
                continue

              words.append(line[start:id + 1])
              start = id + 1

        # fixes bug with cursor going wrong if last character is a space after a letter
        elif id == len(line) - 1 and not line[id - 1].isspace():
          words.append(" ")

      if start < len(line) - 1:
        words.append(line[start:len(line)])

      if len(words) > 0:
        for word in words:

          # Wrap word longer than terminal can display in one line
          while len(word[maxi:]) >= MAX_CHARACTERS:
            if curlength < 1:
              rtext[len(rtext) - 1] += (word[maxi:maxi - 1 + MAX_CHARACTERS])
              curlength = len(word[maxi:maxi + MAX_CHARACTERS])
            else:
              rtext.append(word[maxi:maxi - 1 + MAX_CHARACTERS])
              curlength = len(rtext[len(rtext) - 1])
              dict.insert(len(dict), i)

            # - 1 is needed to wrap the last character in line correctly
            maxi += MAX_CHARACTERS - 1

          # The last part of a long word, that is shorter than line length
          if maxi > 0:
            rtext.append(word[maxi:])
            dict.insert(len(dict), i)
            curlength = len(word[maxi:])
            maxi = 0

          elif curlength + (len(word) + 1) >= MAX_CHARACTERS:
            rtext.append(word)
            dict.insert(len(dict), i)
            curlength = len(word)

          else:
            rtext[len(rtext) - 1] += word
            curlength = curlength + len(word) + 1

      else:
        rtext[len(rtext) - 1] += line
    else:
      rtext[len(rtext) - 1] += line

    rtext.append("")
    # needed to not create unnecessary empty line in rare cases
    curlength = 0
  dict.insert(len(dict), i + 1)
  return rtext, dict

def edit(term, lines: List[str]):
  startrow = row = col = 0
  while True:
    win = get_terminal_size()
    MAX_CHARACTERS = get_terminal_size().columns

    drawdata, dict = word_wrap(lines)

    # gets the right displayed row, accounting for above wrapped lines
    drow = 0
    if row > 0:
      drow -= 2
      for id, line in enumerate(drawdata):
        if dict[id] <= row:
          if dict[id] == row:
            # if future line is a wrapped line
            if (len(dict) > id + 1) and (dict[id + 1] == row):
              drow += 2
              break
          drow += 1
        else:
          break
    looppos = drow
    if len(lines[row]) >= MAX_CHARACTERS:
      addup = 0
      drow -= 1

      for dline in drawdata[looppos:]:

        if col >= addup + len(dline):

          drow += 1
          # fixes bug at end of line moving to next line 1 character too early
          if col == len(lines[row]) and col == addup + len(dline):
            break

          addup += len(dline)
          dcol = col - addup
        else:
          drow += 1
          dcol = col - addup
          break
    else:
      if row > 0:
        drow += 1
      dcol = col

    # handles edge case of space between wrapped words that got moved to next line
    # if cursor is at this space, it makes it display cursor in previous line
    # that makes it more intuitive than characters being typed at another line than the cursor is
    if dcol == 0:
      if len(drawdata[drow]) > 0 and drawdata[drow][0].isspace():
        drow -= 1
        dcol = len(drawdata[drow])

    startrow = min(max(0, drow - 1), startrow)
    startrow = max(drow - win.lines + 2, startrow)

    draw = "\x1B[0K\n".join(l[:win.columns - 1] for l in drawdata[startrow:startrow + win.lines - 1])

    term.write(f"\x1B[2;1H{draw}\x1B[0J\x1B[{drow - startrow + 2};{dcol+1}H")

    keys = list(term.reader())
    combo = ''.join(keys)

    # NOTE: CONTROL key actions could be made more consistent when moving between lines, at cost of much higher code
    # complexity.

    # CONTROL + LEFT (move to next word to left or edge of word, skip empty spaces, if at edge of line,
    # move to upper line)
    if combo == ';5D':
      jumped = False
      # skip empty lines
      if len(lines[row]) > 0:
        indexes = [i for i, c in sorted(enumerate(lines[row]), reverse=True) if c.isspace()]
        index = 0
        for i in indexes:
          index += 1
          if i < col:
            # skip multiple spaces, but only if current column is already at end of word (see lower code)
            if not (lines[row][i - 1].isspace() and lines[row][col - 1].isspace()):
              # jump to end of current word if not at end already
              if not lines[row][col - 1].isspace():
                col = i + 1
              # jump to start of previous word
              elif index < len(indexes):
                col = indexes[index] + 1
              else:
                col = 0
              jumped = True
              break
      if not jumped:
        # jump to end of current line if not at end
        if col > 0:
          col = 0
        # if at end of current line, jump to previous line
        elif row > 0:
          row -= 1
          col = len(lines[row]) - 1
      # skip empty lines
      while (len(lines[row]) == 0) or lines[row].isspace():
        if len(lines) - 1 > 0 and row > 0:
          row -= 1
          col = max(len(lines[row]), 0)
        else:
          break

    # CONTROL + RIGHT (move to next word to right or edge of word, skip empty spaces, if at edge of line,
    # move to lower line)
    elif combo == ';5C':
      if len(lines[row]) > 0:
        indexes = [i for i, c in enumerate(lines[row]) if c.isspace()]

        jumped = False
        for i in indexes:
          if i > col:
            # don't unnecessarily jump to every space if it's a combination of spaces
            if len(lines[row]) > i+1:
              if not lines[row][i+1].isspace():
                col = i + 1
                jumped = True
                break
        if not jumped:
            row += 1
            col = 0
            if len(lines) <= row:
              lines.insert(row, "")

      # skip empty lines
      while (len(lines[row]) == 0) or lines[row].isspace():
        if len(lines) - 1 > row:
          row += 1
        else:
          break

    # OTHER KEYS

    else:
      for key in keys:
        if key == 'ESC':
          return '\n'.join(lines)
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


        elif key == 'UP':
          # supports going UP in wrapped lines correctly
          if drow > 0 and len(lines[row]) > MAX_CHARACTERS:

            # end of wrapped line reached, go to upper line
            if ((dcol - col == 0) or (dcol - col == 1)) and row > 0:
              row -= 1
              # if upper line is a wrapped line or not
              if len(lines[row]) > MAX_CHARACTERS:

                col = (len(lines[row]) - len(drawdata[drow - 1])) + min(col, len(drawdata[drow - 1]))
              else:
                col = min(dcol, len(lines[row]))
            else:
              # if moving to a shorter line than current
              if len(drawdata[drow - 1]) < dcol:
                col -= dcol - len(drawdata[drow - 1])

              col -= dcol + (MAX_CHARACTERS - dcol) - 2
              # accounts for empty area in a word wrapped line
              col += MAX_CHARACTERS - len(drawdata[drow - 1]) - 2
              # fixes bug when going to 1st character at start of message in wrapped line
              col = max(0, col)
          elif row > 0:
            row -= 1
            if len(lines[row]) > MAX_CHARACTERS:
              # moves to upper line while preserving same cursor position (if that line is long enough)
              col = (len(lines[row]) - len(drawdata[drow - 1])) + min(col, len(drawdata[drow - 1]))

            col = min(col, len(lines[row]))

        elif key == 'DOWN':

          # supports going DOWN in wrapped lines correctly
          if row < len(lines) and drow < len(drawdata) - 1 and len(lines[row]) > MAX_CHARACTERS:

            # end of wrapped line reached, go to next line
            eol = col + len(drawdata[drow]) - dcol
            if len(lines[row]) == eol:

              row += 1
              if len(lines) == row:
                lines.insert(row, "")
              col = min(len(drawdata[drow + 1]), dcol)
            else:

              # if moving to a shorter line than current
              if len(drawdata[drow + 1]) < dcol:
                col -= dcol - (len(drawdata[drow + 1]))

              col += dcol + (MAX_CHARACTERS - dcol) - 2

              # if moving to line of single long word that is wrapped
              if len(drawdata[drow]) == MAX_CHARACTERS - 1:
                col += 1

              # accounts for empty area in a word wrapped line
              col -= max(0, MAX_CHARACTERS - len(drawdata[drow]) - 2)
          elif row < len(lines) - 1:
            row += 1
            col = min(col, len(lines[row]))
        elif key == 'ENTER':

          # supports pasting multiple lines
          if len(lines) <= row:
            lines.insert(row, "")

          lines.insert(row + 1, lines[row][col:])
          lines[row] = lines[row][:col]
          col = 0
          row += 1
        elif len(key) == 1:

          # supports pasting multiple lines
          if len(lines) <= row:
            lines.insert(row, "")

          lines[row] = lines[row][:col] + key + lines[row][col:]
          col += 1
