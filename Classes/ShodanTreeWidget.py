from PySide6.QtWidgets import *
from PySide6.QtCore import *
from . import Controller

# Esta clase permite registrar cuando el usuario expande un item para añadir la información adicional.
class ShodanTreeWidget(QTreeWidget):
    def mousePressEvent(self,event):
        clickedIndex = self.indexAt(event.position().toPoint())
        if clickedIndex.isValid():
            vrect = self.visualRect(clickedIndex)
            itemIdentation = vrect.x() - self.visualRect(self.rootIndex()).x()
            if event.position().toPoint().x() < itemIdentation:
                if not self.isExpanded(clickedIndex):
                    itemToAddInfo = self.itemAt(event.position().toPoint())
                    currentIp = itemToAddInfo.text(0)
                    if itemToAddInfo.whatsThis(0) != ' ' and currentIp != "-":
                        QApplication.instance().setOverrideCursor(Qt.CursorShape.BusyCursor)
                        itemToAddInfo.setWhatsThis(0, ' ')
                        itemIndex = self.indexFromItem(itemToAddInfo, 0)
                        self.insertTopLevelItem(itemIndex.row(), itemToAddInfo)
                        # Significa que el usuario quiere expandir un elemento cuya información no ha sido obtenida.
                        if itemToAddInfo != "":
                            shodanMatches = Controller.getAdvanceData(currentIp)
                            neededChild = itemToAddInfo.child(0)
                            # Se añade la información más relevante, posibilidad de información avanzada y añadido al módulo de fuerza bruta.
                            table = Controller.createDeviceInfoTable(shodanMatches, True)
                            self.setItemWidget(neededChild, 0, table)
                        QApplication.instance().restoreOverrideCursor()
                    self.expand(clickedIndex)
                else:
                    self.collapse(clickedIndex)