from PySide6.QtCore import Qt, Slot
from PySide6.QtGui import QKeySequence, QPixmap, QShortcut, QValidator
from PySide6.QtWidgets import QFileDialog, QGridLayout, QLabel, QLineEdit, QPushButton, QSpacerItem, QWidget

from covert import passphrase, pubkey, util
from covert.gui.util import datafile


class Emoji(QLabel):

  def __init__(self):
    QLabel.__init__(self)
    self.pixmaps = [
      QPixmap(datafile(f"emoji-{m}.png")) for m in "think dissatisfied neutral smiling grin".split()
    ]
    self.setAlignment(Qt.AlignCenter)
    self.face(0)

  def face(self, n):
    self.setPixmap(self.pixmaps[n])

class AuthInput(QWidget):

  def __init__(self, app):

    QWidget.__init__(self)
    self.setMinimumWidth(535)
    self.app = app
    self.title = QLabel()
    self.notes = QLabel()
    self.notes.setMinimumWidth(450)
    self.emoji = Emoji()
    self.init_keyinput()
    self.init_passwordinput()

    self.title.setText("<b>Add a recipient key or choose a passphrase to encrypt with.</b>")

    self.layout = QGridLayout(self)
    self.layout.setContentsMargins(11, 11, 11, 11)
    self.layout.addWidget(QLabel("Sender:"), 0, 0)
    self.layout.addWidget(self.siginput, 0, 1)
    self.layout.addWidget(self.skfile, 0, 4)
    self.layout.addWidget(QLabel("Recipient:"), 1, 0)
    self.layout.addWidget(self.pkinput, 1, 1)
    self.layout.addWidget(self.pkadd, 1, 2)
    self.layout.addItem(QSpacerItem(10, 1), 1, 3)
    self.layout.addWidget(self.pkfile, 1, 4)

    self.layout.addWidget(self.emoji, 2, 4, 2, 1)
    self.layout.addWidget(self.title, 2, 0, 1, 3)
    self.layout.addWidget(self.notes, 3, 0, 1, 3)
    self.layout.addWidget(self.pw, 4, 0, 1, 3)
    self.layout.addWidget(self.addbutton, 4, 4)



  def init_passwordinput(self):
    self.pw = QLineEdit()
    self.addbutton = QPushButton()
    self.addbutton.clicked.connect(self.addpassword)
    QShortcut(QKeySequence("Return"), self.pw, context=Qt.WidgetShortcut).activated.connect(self.addpassword)
    QShortcut(QKeySequence("Tab"), self.pw, context=Qt.WidgetShortcut).activated.connect(self.tabcomplete)
    QShortcut(QKeySequence("Ctrl+H"), self.pw, context=Qt.WidgetShortcut).activated.connect(self.togglehide)
    self.validator = PWValidator(self)
    self.pw.setValidator(self.validator)
    self.pw.setEchoMode(QLineEdit.EchoMode.Password)
    self.visible = False
    self.validator.validate("", 0)

  def init_keyinput(self):
    self.siginput = QLineEdit()
    self.siginput.setDisabled(True)
    self.siginput.setReadOnly(True)
    self.siginput.setFixedWidth(260)
    self.pkinput = QLineEdit()
    self.pkinput.setFixedWidth(260)
    self.pkinput.setPlaceholderText("SSH/Minisign/Age pubkey, or github:user")

    self.pkadd = QPushButton('Add')
    self.pkfile = QPushButton('Open keyfile')
    self.skfile = QPushButton('Open keyfile')

    QShortcut(QKeySequence("Return"), self.pkinput, context=Qt.WidgetShortcut).activated.connect(self.decodepk)
    self.pkadd.clicked.connect(self.decodepk)
    self.pkfile.clicked.connect(self.loadpk)
    self.skfile.clicked.connect(self.loadsk)


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
    self.app.passwords.add(passphrase.pwhash(util.encode(pw)))
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

  @Slot()
  def decodepk(self):
    # In CLI github is considered a file, and here not (because not from file dialog)
    # Need to handle this logic mismatch here
    keystr = self.pkinput.text()
    if keystr.startswith('github:'):
      self.app.recipients |= set(pubkey.read_pk_file(keystr))
    else:
      self.app.recipients.add(pubkey.decode_pk(keystr))
      self.app.update_encryption_views()
    self.pkinput.setText("")
    if self.app.recipients:
      self.title.setText("<b>Recipient public key added.</b>")
      self.notes.setText("\n\n")

  @Slot()
  def loadpk(self):
    file = QFileDialog.getOpenFileName(
      self, "Covert - Open public key", "", "SSH, Minisign and Age public keys (*.pub);;All files (*)"
    )[0]
    if not file:
      return
    self.app.recipients |= set(pubkey.read_pk_file(file))
    self.app.update_encryption_views()
    if self.app.recipients:
      self.title.setText("<b>Recipient public key added.</b>")
      self.notes.setText("\n\n")

  @Slot()
  def loadsk(self):
    file = QFileDialog.getOpenFileName(self, "Covert - Open secret key", "",
      "SSH, Minisign and Age private keys (*)")[0]
    if not file:
      return
    self.app.signatures = set(pubkey.read_sk_file(file))
    self.app.update_encryption_views()




class PWValidator(QValidator):

  def __init__(self, pwinput):
    QValidator.__init__(self)
    self.pwinput = pwinput

  def validate(self, text, pos):
    hints, valid = passphrase.pwhints(text)
    hints = hints.rstrip()
    hints += (3 - hints.count('\n')) * '\n'
    t, n = hints.split('\n', 1)
    self.pwinput.title.setText(f"<b>{t}</b>")
    self.pwinput.notes.setText(n)
    self.pwinput.addbutton.setText("Add" if text else "Random")
    self.pwinput.addbutton.setEnabled(valid or not text)
    if not text: quality = 0
    elif not valid: quality = 1
    elif "centuries" in t: quality = 4
    elif "years" in t: quality = 3
    else: quality = 2
    self.pwinput.emoji.face(quality)
    return QValidator.Acceptable if valid else QValidator.Intermediate

