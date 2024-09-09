from PySide6.QtWidgets import *
from PySide6.QtGui import *
from PySide6.QtWebEngineWidgets import QWebEngineView
from pathlib import Path
import sys
import os
import ctypes

# Creación de la aplicación
app = QApplication(sys.argv)

# Se importan las clases de las diversas ventanas de la aplicación
from Classes.AddIpManuallyWindow import AddIpManuallyWindow
from Classes.ShodanKeyWindow import ShodanKeyWindow
from Classes.BruteforceWindow import BruteforceWindow
from Classes.ShodanQueriesWindow import ShodanQueriesWindow
from Classes.HowToWindow import HowToWindow

# Esta función permite actualizar los dispositivos guardados siempre que se quiera acceder.
def bruteforceIsClicked(tabIndex, bruteforceWindow):
    if tabIndex == 1:
        bruteforceWindow.initializeTreeWidget()

# Función para crear la interfaz
def createGui():
    # Indicar que el directorio de trabajo sea en el que se encuentra el script
    abspath = os.path.abspath(__file__)
    dname = os.path.dirname(abspath)
    os.chdir(dname)
    # Cambio del nombre y el icono de la aplicación
    app.setApplicationDisplayName("Neo-Halligan")
    app.setFont(QFont("Roboto", 10))
    pixmap = QPixmap()
    pixmap.loadFromData(Path(os.path.abspath("Ico/icon.png")).read_bytes())
    appIcon = QIcon(pixmap)
    app.setWindowIcon(appIcon)
    # Permite tener el icono de la aplicación en la barra de tareas de Windows
    if os.name == "nt":
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID('Jfmm.UNIR.1')
    # Creamos la estructura básica de la aplicación
    mainWindow = QMainWindow()
    tabLayout = QTabWidget()
    tabLayout.setMinimumSize(770,394)
    shodanQueriesWindow = ShodanQueriesWindow(tabLayout)
    howToWindow = HowToWindow(tabLayout)
    bruteforceWindow = BruteforceWindow(tabLayout)
    ipWindow = AddIpManuallyWindow(tabLayout)
    shodanKeyWindow = ShodanKeyWindow(tabLayout)
    tabLayout.addTab(shodanQueriesWindow, "Shodan queries")
    tabLayout.addTab(bruteforceWindow, "Brute force")
    tabLayout.addTab(ipWindow, "Add IPs manually")
    tabLayout.addTab(shodanKeyWindow, "Shodan key")
    tabLayout.addTab(howToWindow, "How to use")
    tabLayout.currentChanged.connect(lambda l=tabLayout.currentIndex(), b=bruteforceWindow: bruteforceIsClicked(l, b)) # lambda b=device: Controller.createAdvancedInfoPopup(self, b)
    mainWindow.setCentralWidget(tabLayout)
    mainWindow.show()
    # Indicamos el tiempo de refresco de la interfaz gráfica
    app.exec()

createGui()
