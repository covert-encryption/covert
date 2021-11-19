from PySide6.QtCore import Qt, Slot
from PySide6.QtGui import QKeySequence, QPixmap, QShortcut, QValidator
from PySide6.QtWidgets import QGridLayout, QLabel, QLineEdit, QPushButton, QWidget

from covert import passphrase
from covert.gui.util import datafile


class PasswordInput(QWidget):

  def __init__(self, app):

    class PWValidator(QValidator):

      def validate(that, text, pos):
        self.setFixedWidth(535)
        hints, valid = passphrase.pwhints(text)
        hints = hints.rstrip()
        hints += (3 - hints.count('\n')) * '\n'
        t, n = hints.split('\n', 1)
        title.setText(f"<b>{t}</b>")
        notes.setText(n)
        self.addbutton.setText("Add" if text else "Random")
        self.addbutton.setEnabled(valid or not text)
        if not text:
          emoji.setPixmap(quality[0])
        elif not valid:
          emoji.setPixmap(quality[1])
        elif "centuries" in t:
          emoji.setPixmap(quality[4])
        elif "years" in t:
          emoji.setPixmap(quality[3])
        else:
          emoji.setPixmap(quality[2])
        return QValidator.Acceptable if valid else QValidator.Intermediate

    QWidget.__init__(self)
    self.app = app
    self.title = title = QLabel()
    self.notes = notes = QLabel()
    notes.setMinimumWidth(450)
    quality = [
      QPixmap(datafile('emoji-think.png')),
      QPixmap(datafile('emoji-dissatisfied.png')),
      QPixmap(datafile('emoji-neutral.png')),
      QPixmap(datafile('emoji-smiling.png')),
      QPixmap(datafile('emoji-grin.png')),
    ]
    emoji = QLabel()
    emoji.setAlignment(Qt.AlignCenter)
    self.pw = QLineEdit()
    self.addbutton = QPushButton()
    self.addbutton.clicked.connect(self.addpassword)
    QShortcut(QKeySequence("Return"), self.pw, context=Qt.WidgetShortcut).activated.connect(self.addpassword)
    QShortcut(QKeySequence("Tab"), self.pw, context=Qt.WidgetShortcut).activated.connect(self.tabcomplete)
    QShortcut(QKeySequence("Ctrl+H"), self.pw, context=Qt.WidgetShortcut).activated.connect(self.togglehide)
    self.validator = PWValidator()
    self.validator.validate("", 0)
    self.visible = False
    self.pw.setValidator(self.validator)
    self.pw.setEchoMode(QLineEdit.EchoMode.Password)
    self.layout = QGridLayout(self)
    self.layout.setContentsMargins(10, 10, 10, 10)
    self.layout.addWidget(emoji, 1, 1, 2, 1)
    self.layout.addWidget(title, 1, 0)
    self.layout.addWidget(notes, 2, 0)
    self.layout.addWidget(self.pw, 3, 0)
    self.layout.addWidget(self.addbutton, 3, 1)

  @Slot()
  def togglehide(self):
    self.visible = not self.visible
    self.pw.setEchoMode(QLineEdit.EchoMode.Normal if self.visible else QLineEdit.EchoMode.Password)

  @Slot()
  def addpassword(self):
    pw = self.pw.text()
    if not pw:
      pw = passphrase.generate()
      note = f"Passphrase added: {pw}"
    else:
      hint, valid = passphrase.pwhints(pw)
      if not valid:
        self.notes.setText(2*'\n' + "A stronger password is required.")
        return
      note = "Passphrase added."
    self.app.passwords.add(pw)
    self.app.window.plaintext.setFocus()
    self.pw.setText("")
    self.validator.validate(pw, 0)
    self.title.setText("")
    self.notes.setText(2*'\n' + note)
    self.app.update_encryption_views()

  @Slot()
  def tabcomplete(self):
    pw, pos, hint = passphrase.autocomplete(self.pw.text(), self.pw.cursorPosition())
    self.pw.setText(pw)
    self.pw.setCursorPosition(pos)
    if hint:
      self.notes.setText(2*'\n' + 'Autocomplete: ' + hint)
