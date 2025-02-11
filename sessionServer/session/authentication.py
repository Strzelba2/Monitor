from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from .models import Server
import logging

logger = logging.getLogger('django')

class IPWhitelistAuthentication(BaseAuthentication):
    """
    Custom authentication class that verifies if the request originates from a whitelisted IP.

    The authentication process checks the client's IP address against the server's registered
    IP address in the database. If the IP does not match or the server is not trusted, access is denied.
    """
    def authenticate(self, request):
        """
        Authenticates the request by verifying the client's IP address.

        Args:
            request (HttpRequest): The incoming HTTP request.

        Returns:
            tuple[None, None]: If authentication is successful, it returns (None, None), 
            indicating no specific user authentication but validation is complete.

        Raises:
            AuthenticationFailed: If the server is not found, the IP is not whitelisted, 
            or the server is not trusted.
        """
        ip_address = request.META.get('HTTP_X_FORWARDED_FOR')
        
        if ip_address:
            logger.debug(f"Extracted IP from HTTP_X_FORWARDED_FOR: {ip_address}")
            ip_address = ip_address.split(',')[0]
        else:
            ip_address = request.META.get('REMOTE_ADDR')
            logger.debug(f"Extracted IP from REMOTE_ADDR: {ip_address}")
            
        ip = request.META.get('REMOTE_ADDR')

        server_name = request.path.strip("/").split("/")[-1]
        
        logger.debug(f"Extracted server name from request path: {server_name}")
        
        try:
            server = Server.objects.get(name=server_name)
        except Server.DoesNotExist:
            logger.error(f"Server '{server_name}' not found in the database.")
            raise AuthenticationFailed(f"Server '{server_name}' not found.")
        
        logger.debug(f"Client IP: {ip_address} | Expected Server IP: {server.ip_address}")
        
        if ip != server.ip_address:
            logger.error(f"Access denied: Client IP '{ip_address}' does not match the registered server IP.")
            raise AuthenticationFailed('Your IP is not allowed.')
        
        if not server.trusty:
            logger.error('The server is not trusted, please contact the administrator.')
            raise AuthenticationFailed('The server is not trusted, please contact the administrator.')
        
        return None, None