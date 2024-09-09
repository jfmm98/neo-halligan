from PySide6.QtWidgets import *
from PySide6.QtCore import *
from . import Controller
import ping3

# Clase para la ventana que permite guardar la key de Shodan.
class AddIpManuallyWindow(QWidget):

    userInputElement = QLineEdit("") 
    saveKeyElement = QPushButton("Save IP")
    infoLabel = QLabel("""If the IP is on Shodan and the key is valid,<br> 
                          all the data will come from Shodan. However,<br>
                          if there is no data about the IP, a nmap run<br> 
                          will be done in order to obtain data. However,<br>
                          that nmap run will only cover the default ports<br> 
                          of the protocols available on the brute force module.<br>
                          If you want to check your own device, write localhost.""")
    layoutW1 = QVBoxLayout()
    timer = QTimer()

    def __init__(self, parent):
        super().__init__()
        self.userInputElement.setPlaceholderText("Add IP")
        self.userInputElement.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        self.infoLabel.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        self.saveKeyElement.pressed.connect(self.saveIP)
        self.layoutW1.addWidget(self.userInputElement)
        self.layoutW1.addWidget(self.saveKeyElement)
        self.layoutW1.addWidget(self.infoLabel)
        self.setLayout(self.layoutW1)
        self.setWindowTitle("Add IP Manually")
    
    def saveIPAux(self):
        QApplication.instance().setOverrideCursor(Qt.CursorShape.BusyCursor)
        userInput = self.userInputElement.text().strip()
        layout = QVBoxLayout()
        infoPopup = QDialog(self)
        ipValid = True
        if ping3.ping(userInput) == False:
            ipValid = False
        if ipValid or ipValid == "localhost":
            saveIpInfo = Controller.saveIpToBruteforce(userInput)
            infoPopup.setWindowTitle(saveIpInfo[0])
            layout.addWidget(QLabel(saveIpInfo[1]))
        else:
            infoPopup.setWindowTitle("IP not valid")
            layout.addWidget(QLabel("IP is not valid, please check it and try again"))
        QApplication.instance().restoreOverrideCursor()
        closeButton = QDialogButtonBox(QDialogButtonBox.Ok)
        closeButton.accepted.connect(infoPopup.accept)
        layout.addWidget(closeButton)
        infoPopup.setLayout(layout)
        infoPopup.exec()
    
    def saveIP(self):
        self.timer.singleShot(250, self.saveIPAux)