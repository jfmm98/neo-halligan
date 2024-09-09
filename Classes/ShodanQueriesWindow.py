from PySide6.QtWidgets import *
from PySide6.QtCore import *
from PySide6.QtWebEngineWidgets import QWebEngineView
from . import ShodanTreeWidget
from . import Controller

""" Esta clase permite al usuario obtener dispositivos de Shodan a partir de una query
    y añadir estos dispositivos al módulo de ataque de fuerza bruta."""
class ShodanQueriesWindow(QWidget):
    
    userQuery = QLineEdit("") 
    searchElement = QPushButton("Search")
    layoutW1 = QVBoxLayout()
    layoutW2 = QHBoxLayout()
    treeWidget = ShodanTreeWidget.ShodanTreeWidget()
    numberOfResults = QComboBox()
    timer = QTimer()

    # Se define el constructor de la clase. En este, se crean y gestionan los diversos elementos de la interfaz.
    def __init__(self, parent):
        super().__init__()
        self.userQuery.setPlaceholderText("Shodan query")
        self.userQuery.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        self.treeWidget.setColumnHidden(0, True)
        self.numberOfResults.addItems(["25", "50", "100", "200"])
        self.searchElement.clicked.connect(self.scheduleShodanQuery)
        self.layoutW2.addWidget(self.userQuery)
        self.layoutW2.addWidget(self.searchElement)
        self.layoutW2.addWidget(self.numberOfResults)
        self.layoutW1.addLayout(self.layoutW2)
        self.layoutW1.addWidget(self.treeWidget)
        self.setLayout(self.layoutW1)
        self.setWindowTitle("Shodan queries")
    
    # Permite lanzar la función que se encargará de realizar la query de Shodan.
    def scheduleShodanQuery(self):
        self.timer.singleShot(250, self.doShodanQuery)
    
    # Se realiza la query que ha indicado el usuario, mostrando la información obtenida.
    def doShodanQuery(self):
        QApplication.instance().setOverrideCursor(Qt.CursorShape.BusyCursor)
        userQuery = self.userQuery.text().strip()
        numberOfResultsToGet = int(self.numberOfResults.currentText())
        queryFailed = False
        try:
            shodanData = Controller.realizeShodanQuery(userQuery, numberOfResultsToGet)
        except Exception as e:
            Controller.createPopup(self, "Shodan error", str(e))
            queryFailed = True
        if not queryFailed:
            if len(shodanData['matches']) == 0:
                Controller.createPopup(self, "No results", "The query did not obtain results.")
            else:
                self.createTreeWidget(shodanData)
        QApplication.instance().restoreOverrideCursor()

    # Permite añadir los dispositivos encontrados mediante una búsqueda en Shodan.
    def createTreeWidget(self, shodanData):
        self.treeWidget.clear()
        self.treeWidget.setColumnHidden(0, False)
        self.treeWidget.setColumnCount(1)
        self.treeWidget.setHeaderLabels(["Devices"])
        self.treeWidget.header().setDefaultAlignment(Qt.AlignmentFlag.AlignHCenter)
        shodanMatches = shodanData['matches']
        items = []
        # Añadir hijos
        for i in range(len(shodanMatches)):
            ip = shodanMatches[i]["ip_str"]
            # Este nodo seria la ip
            treeItem = QTreeWidgetItem([ip])
            # Este nodo es un placeholder para añadir la información cuando el elemento sea abierto
            childItem = QTreeWidgetItem(["-"])
            # Añadir aquí botones
            childItem2 = QTreeWidgetItem(["--"])
            treeItem.addChild(childItem)
            treeItem.addChild(childItem2)
            advancedButton = QPushButton("Advanced info")
            addBruteforceButton = QPushButton("Add bruteforce")
            advancedButton.pressed.connect(lambda b=ip: Controller.createAdvancedInfoPopup(self, b))
            addBruteforceButton.pressed.connect(lambda b=ip: self.saveIpToBruteforce(b))
            bothButtons = QWidget()
            bothButtonsLayout = QHBoxLayout()
            bothButtonsLayout.addWidget(advancedButton)
            bothButtonsLayout.addWidget(addBruteforceButton)
            bothButtons.setLayout(bothButtonsLayout)
            self.treeWidget.setItemWidget(childItem2, 0, bothButtons)
            items.append(treeItem)
            # self.treeWidget.insertTopLevelItem(i, treeItem)
        self.treeWidget.insertTopLevelItems(0, items)
   
    def saveIpToBruteforce(self, neededIp):
        QApplication.instance().setOverrideCursor(Qt.CursorShape.BusyCursor)
        a = Controller.saveIpToBruteforce(neededIp)
        QApplication.instance().restoreOverrideCursor()
        Controller.createPopup(self,a[0],a[1])