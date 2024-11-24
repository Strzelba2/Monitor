from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from .models import Server

class IPWhitelistAuthentication(BaseAuthentication):
    def authenticate(self, request):
        ip = request.META.get('REMOTE_ADDR')
        server_name = request.data.get('server_name')
        
        server = Server.objects.get(name=server_name)
        
        if ip != server.ip_address:
            raise AuthenticationFailed('Your IP is not allowed.')
        
        if not server.trusty:
            raise AuthenticationFailed('The server is not trusted, please contact the administrator.')
        
        return None, None