import os
from io import BytesIO

from PySide6.QtCore import Qt, Slot
from PySide6.QtGui import QKeySequence, QPixmap, QShortcut, QStandardItem, QStandardItemModel, QValidator
from PySide6.QtWidgets import *

from covert import passphrase, pubkey, util
from covert.archive import Archive
from covert.blockstream import encrypt_file
from covert.gui import res
from covert.gui.util import datafile
from covert.gui.widgets import EncryptToolbar, MethodsWidget
from covert.util import ARMOR_MAX_SIZE


class NewMessageView(QWidget):

  def __init__(self, app):
    QWidget.__init__(self)

    self.files = set()
    self.recipients = set()
    self.signatures = set()
    self.identities = set()
    self.passwords = set()
    self.generated = {}

    self.app = app
    self.auth = AuthInput(app, self)
    self.methods = MethodsWidget(self)
    self.plaintext = QPlainTextEdit()
    self.plaintext.setTabChangesFocus(True)
    self.attachments = QListView()
    self.attmodel = QStandardItemModel(self)
    self.attachments.setModel(self.attmodel)
    self.attachments.setMaximumHeight(120)
    self.attachments.setWrapping(True)

    self.layout = QGridLayout(self)
    self.layout.setContentsMargins(0, 0, 0, 0)
    self.layout.setSpacing(0)
    self.layout.addItem(QSpacerItem(0, 0, QSizePolicy.Expanding, QSizePolicy.Fixed), 0, 1)
    self.layout.addItem(QSpacerItem(0, 0, QSizePolicy.Expanding, QSizePolicy.Fixed), 0, 6)
    self.layout.addItem(QSpacerItem(0, 11), 1, 2, 1, 4)
    self.layout.addWidget(self.auth, 2, 2, 1, 4)
    self.layout.addItem(QSpacerItem(0, 11), 3, 2, 1, 4)
    self.layout.addWidget(self.methods, 4, 0, 1, -1)
    self.layout.addWidget(self.plaintext, 5, 0, 1, -1)
    self.layout.addWidget(self.attachments, 6, 0, 1, -1)
    self.layout.addWidget(EncryptToolbar(app, self), 7, 0, 1, -1)

  def clear_message(self):
    self.plaintext.setPlainText("")
    self.files = {}
    self.update_views()
    self.plaintext.setFocus()

  def update_views(self):
    if len(self.recipients) + len(self.passwords) > 20:
      self.recipients = set(list(self.recipients)[:20])
      self.passwords = set(list(self.passwords)[:20 - len(self.recipients)])
      self.app.flash("Some recipients were discarded, can only have 20 recipients.")

    self.auth.siginput.setText(', '.join(str(k) for k in self.signatures) or "Anonymous (no signature)")
    # Avoid user confusion by hiding the password input once there are recipients or a password.
    # Still allows adding a passphrase first and then public key recipients, in case needed.
    addpw = not self.recipients and not self.passwords
    self.auth.notes.setVisible(addpw)
    self.auth.pw.setVisible(addpw)
    self.auth.addbutton.setVisible(addpw)
    if addpw:
      # Update password hints
      self.auth.validator.validate("", 0)
      self.auth.title.setText("<b>Add a recipient key or choose a passphrase to encrypt with.</b>")
    self.methods.deleteLater()
    self.methods = MethodsWidget(self)
    self.layout.addWidget(self.methods, 4, 0, 1, -1)

    self.attachments.setVisible(bool(self.files))
    self.attmodel.clear()
    for a in list(sorted(self.files)):
      icon = res.icons.foldericon if os.path.isdir(a) else res.icons.fileicon
      item = QStandardItem(icon, a.split('/')[-1])
      self.attmodel.appendRow(item)

  def validate(self):
    if self.plaintext.toPlainText().strip() or self.files: return True
    self.app.flash("Type in a message or add some files first.")
    return False

  def encrypt(self, outfile):
    # Process the message, prune surrounding whitespace
    msg = self.plaintext.toPlainText()
    msg = '\n'.join([l.rstrip() for l in msg.split('\n')]).strip('\n')
    try:
      msg = util.encode(msg)
      a = Archive()
      files = list(sorted(self.files))
      a.file_index([msg] + files if msg else files)
      if self.signatures:
        a.index['s'] = [s.edpk for s in self.signatures]
      # Output files
      if isinstance(outfile, BytesIO) and a.total_size > ARMOR_MAX_SIZE:
        raise ValueError("The data is too large for ASCII Armoring. Save as Covert Binary instead.")
      wideopen = not (self.passwords or self.recipients)
      # Main processing
      for block in encrypt_file((wideopen, self.passwords, self.recipients, self.signatures), a.encode, a):
        outfile.write(block)
    except ValueError as e:
      self.app.flash(str(e))
      raise

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

  def __init__(self, app, view):

    QWidget.__init__(self)
    self.setMinimumWidth(535)
    self.app = app
    self.view = view
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
    visible = False
    if not pw:
      pw = passphrase.generate()
      visible = True
    else:
      hint, valid = passphrase.pwhints(pw)
      if not valid:
        self.notes.setText(2*'\n' + "A stronger password is required.")
        return
    pwhash = passphrase.pwhash(util.encode(pw))
    self.view.passwords.add(pwhash)
    if visible:
      self.view.generated[pwhash] = pw
    self.view.plaintext.setFocus()
    self.pw.setText("")
    self.validator.validate(pw, 0)
    self.title.setText("")
    self.notes.setText(2*'\n')
    self.view.app.flash("Passphrase added.")
    self.view.update_views()

  @Slot()
  def tabcomplete(self):
    pw, pos, hint = passphrase.autocomplete(self.pw.text(), self.pw.cursorPosition())
    self.pw.setText(pw)
    self.pw.setCursorPosition(pos)
    if hint:
      self.app.flash(f"Autocomplete: {hint}")

  @Slot()
  def decodepk(self):
    # In CLI github is considered a file, and here not (because not from file dialog)
    # Need to handle this logic mismatch here
    keystr = self.pkinput.text()
    try:
      if keystr.startswith('github:'):
        self.app.recipients |= set(pubkey.read_pk_file(keystr))
      else:
        self.view.recipients.add(pubkey.decode_pk(keystr))
        self.view.update_views()
    except ValueError as e:
      self.app.flash(str(e))
      return
    self.pkinput.setText("")
    if self.app.recipients:
      self.app.flash("Recipient public key added.")

  @Slot()
  def loadpk(self):
    file = QFileDialog.getOpenFileName(
      self, "Covert - Open public key", "", "SSH, Minisign and Age public keys (*.pub);;All files (*)"
    )[0]
    if not file:
      return
    try:
      self.view.recipients |= set(pubkey.read_pk_file(file))
    except ValueError as e:
      self.app.flash(str(e))
      return
    self.view.update_views()
    if self.view.recipients:
      self.app.flash("Recipient public key added.")
      self.title.setText("")

  @Slot()
  def loadsk(self):
    file = QFileDialog.getOpenFileName(self, "Covert - Open secret key", "",
      "SSH, Minisign and Age private keys (*)")[0]
    if not file:
      return
    try:
      self.view.signatures = set(pubkey.read_sk_file(file))
    except ValueError as e:
      self.app.flash(str(e))
      return
    self.view.update_views()


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
