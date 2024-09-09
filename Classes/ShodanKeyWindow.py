from PySide6.QtWidgets import *
from PySide6.QtCore import *
from . import Controller

# Clase para la ventana que permite guardar la key de Shodan.
class ShodanKeyWindow(QWidget):

    userInputElement = QLineEdit("") 
    showCurrentKeyElement = QLabel("")
    saveKeyElement = QPushButton("Save Key")
    layoutW1 = QVBoxLayout()
    timer = QTimer()

    # Se define el constructor de la clase. En este, se crean y gestionan los diversos elementos de la interfaz.
    def __init__(self, parent):
        super().__init__()
        currentKey = Controller.getCurrentShodanKey()
        self.showCurrentKeyElement.setText("Current Key: " + currentKey)
        self.userInputElement.setPlaceholderText("Add Shodan Key")
        self.userInputElement.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        self.showCurrentKeyElement.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        self.saveKeyElement.pressed.connect(self.saveKey)
        self.layoutW1.addWidget(self.userInputElement)
        self.layoutW1.addWidget(self.saveKeyElement)
        self.layoutW1.addWidget(self.showCurrentKeyElement)
        self.setLayout(self.layoutW1)
        self.setWindowTitle("Shodan key")
    
    """ Esta función permite guardar la key que indique el usuario. La confirmación o la indicación del error de esta key
        se mostrará al usuario mediante un pop up."""
    def saveKeyAux(self):
        QApplication.instance().setOverrideCursor(Qt.CursorShape.BusyCursor)
        userInput = self.userInputElement.text()
        setKeyInfo = Controller.setCurrentShodanKey(userInput)
        QApplication.instance().restoreOverrideCursor()
        # Generamos un popup con la información necesaria para el usuario
        infoPopup = QDialog(self)
        infoPopup.setWindowTitle("Key Info")
        layout = QVBoxLayout()
        layout.addWidget(QLabel(setKeyInfo))
        closeButton = QDialogButtonBox(QDialogButtonBox.Ok)
        closeButton.accepted.connect(infoPopup.accept)
        layout.addWidget(closeButton)
        infoPopup.setLayout(layout)
        infoPopup.exec()
        self.showCurrentKeyElement.setText("Current Key: " + Controller.getCurrentShodanKey())
    
    # Esta función hace trigger de la función principal mediante un timer.
    def saveKey(self):
        self.timer.singleShot(250, self.saveKeyAux)