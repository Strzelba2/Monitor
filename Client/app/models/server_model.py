from PyQt6.QtCore import QAbstractTableModel, Qt, QModelIndex, pyqtSignal
from app.models.data_models import Server
import logging

logger = logging.getLogger(__name__)

class ServersModel(QAbstractTableModel):
    """
    A table model representing a list of servers.

    This model provides server information such as name, IP address, location, 
    and an action column for interaction.
    """
    dataChanged = pyqtSignal(QModelIndex, QModelIndex)

    def __init__(self, parent=None) -> None:
        """
        Initializes the ServersModel with an empty list of servers.

        Args:
            parent (QObject, optional): The parent QObject. Defaults to None.
        """
        super().__init__(parent)
        self.servers = []
        logger.info("ServersModel initialized with an empty server list.")

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        """
        Returns the number of rows in the model (number of servers).

        Args:
            parent (QModelIndex, optional): The parent index. Defaults to QModelIndex().

        Returns:
            int: Number of servers in the model.
        """
        return len(self.servers)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        """
        Returns the number of columns in the model.

        Args:
            parent (QModelIndex, optional): The parent index. Defaults to QModelIndex().

        Returns:
            int: The number of columns (4: Name, IP Address, Location, Action).
        """
        return 4  

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole):
        """
        Returns the data for a given index and role.

        Args:
            index (QModelIndex): The model index.
            role (int, optional): The Qt role for data retrieval. Defaults to Qt.ItemDataRole.DisplayRole.

        Returns:
            Any: The requested data or None if invalid.
        """
        if not index.isValid() or not (0 <= index.row() < len(self.servers)):
            logger.warning(f"Invalid index requested: {index}")
            return None

        server = self.servers[index.row()]
        column = index.column()

        if role == Qt.ItemDataRole.DisplayRole:
            if column == 0:
                return server.name
            elif column == 1:
                return server.ip_address
            elif column == 2:
                return server.location
            elif column == 3:
                return "Subscribe"
            
        if role == Qt.ItemDataRole.UserRole:  
            return server.name
        
        return None
    
    def roleNames(self):
        """
        Returns the role names for the model.

        Returns:
            dict[int, bytes]: A dictionary mapping role IDs to names.
        """
        roles = super().roleNames()
        roles[Qt.ItemDataRole.UserRole] = b"name"
        return roles

    def headerData(self, section: int, orientation, role: int = Qt.ItemDataRole.DisplayRole):
        """
        Returns the header data for a given section and orientation.

        Args:
            section (int): The index of the header section.
            orientation (Qt.Orientation): The orientation (horizontal or vertical).
            role (int, optional): The Qt role for data retrieval. Defaults to Qt.ItemDataRole.DisplayRole.

        Returns:
            Any: The header label or None if invalid.
        """
        if role == Qt.ItemDataRole.DisplayRole:
            if orientation == Qt.Orientation.Horizontal:
                return ["Name", "IP Address", "Location","action"][section]
            elif orientation == Qt.Orientation.Vertical:
                return f"{section + 1}"
        return None

    def load_servers(self, server_data: list[dict]) -> None:
        """
        Loads a list of servers from a given list of dictionaries.

        Args:
            server_data (list[dict]): A list of dictionaries containing server data.
        """
        logger.info(f"Loading {len(server_data)} servers into the model.")
        self.beginResetModel()
        self.servers = [Server(**data) for data in server_data]
        self.endResetModel()
        logger.debug("Servers successfully loaded into the model.")