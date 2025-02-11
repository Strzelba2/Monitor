import logging

logger = logging.getLogger(__name__)

class Server:
    """
    Represents a server with basic attributes such as name, IP address, and location.
    """

    def __init__(self, name: str, ip_address: str, location: str) -> None:
        """
        Initializes a new Server instance.

        Args:
            name (str): The name of the server.
            ip_address (str): The IP address of the server.
            location (str): The physical or logical location of the server.
        """
        logger.info(f"Initializing server: name={name}, ip_address={ip_address}, location={location}")
        
        self.name: str = name
        self.ip_address: str = ip_address
        self.location: str = location

        logger.debug(f"Server initialized: {self}")
    
    def __repr__(self) -> str:
        """
        Returns a string representation of the Server instance.

        Returns:
            str: A formatted string containing the server's attributes.
        """
        return f"Server(name={self.name}, ip_address={self.ip_address}, location={self.location})"