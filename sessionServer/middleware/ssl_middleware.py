from django.conf import settings
from django.http import JsonResponse
from rest_framework import status
from oauth2_provider.models import AccessToken
from django.contrib.auth import get_user_model
from userauth.models import User
from session.models import Server
from utils.responses import formatted_response
import json
import logging
import os


logger = logging.getLogger('django')



class SSLMiddleware:
    """
    Middleware to enforce SSL/TLS connections and validate client certificates.
    """
    def __init__(self, get_response):
        """
        Initialize the SSLMiddleware.
        
        Args:
            get_response (callable): The next middleware or view in the Django request-response cycle.
        """
        self.get_response = get_response
        
    def veryfy_request(self,request):
        """
        Verify if response should by JsonResponse or TemplateResponse  based on its content type.
        
        Args:
            request (HttpRequest): The incoming HTTP request.
        """
        logger.debug("Verifying request content type")
        if request.META.get('HTTP_ACCEPT', '').startswith('text/html'):
            logger.info("Browser access attempt detected")
            return formatted_response(
                            request, 
                            {'error': 'Browser access not allowed'},
                            template_name='error.html',
                            status_code=status.HTTP_403_FORBIDDEN)

    def __call__(self, request):
        """
        Process incoming requests, enforcing HTTPS and validating client certificates.
        
        Args:
            request (HttpRequest): The incoming HTTP request.
        
        Returns:
            HttpResponse: The processed response, or an error response if validation fails.
        """
        logger.debug("SSLMiddleware invoked for request")
        
        # Check if HTTPS is required
        if os.environ.get('REQUIRE_HTTPS', 'true').lower() == 'true':
            logger.debug("REQUIRE_HTTPS is set to true")

            logger.debug(f"{request.META}")
            
            # Verify if the request is secure (HTTPS)
            if not request.is_secure() and settings.SECURE_SSL_REDIRECT:
                logger.warning("Insecure request attempted on HTTPS-only route")
                return formatted_response(
                                    request,
                                    {'error': 'Only HTTPS connections are allowed.'}, 
                                    template_name='error.html',
                                    status_code=status.HTTP_403_FORBIDDEN)
            
            # Get the request path to determine special handling

            path = request.path.strip('/').split('/')[0]
   
            client_cn = request.META.get("HTTP_X_SSL_CLIENT_CN")
            
            logger.debug(f"Request path is {path} for {client_cn}")

            if not client_cn:
                logger.warning("Client certificate CN not provided in headers")
                return formatted_response(
                                    request, 
                                    {'error': 'not a valid certificate.'},
                                    template_name='error.html',
                                    status_code=status.HTTP_401_UNAUTHORIZED)
                
            if path in ["updateServer","verifySession"] :
                logger.debug("Processing updateServer or verifySession path")
                logger.debug(f" path: {request.path}")

                server_exists = Server.objects.filter(name=client_cn).exists()
                if not server_exists:
                    logger.warning(f"Server {client_cn} does not exist in database")
                    return JsonResponse({'error': 'Invalid server name'}, status=status.HTTP_401_UNAUTHORIZED)
                
                logger.debug(f"Server {client_cn} validation successful")
                return self.get_response(request)
            
            if not User.is_user_allowed(client_cn):
                logger.warning('Unauthorized user attempt detected')
                return formatted_response(
                                    request, 
                                    {'error': 'not a valid user'},
                                    template_name='error.html',
                                    status_code=status.HTTP_401_UNAUTHORIZED)

            # Handle login path - validate client CN and username
            if path == "login":
                logger.debug("Processing /login path")
                
                response = self.veryfy_request(request)
                if response:
                    return response

                # Handle username extraction based on content type
                try:
                    body = json.loads(request.body)
                    username = body.get('username')
                except json.JSONDecodeError:
                    logger.error("Invalid JSON received in login request")
                    return JsonResponse({'error': 'Invalid JSON'}, status=status.HTTP_403_FORBIDDEN)

                if not username:
                    logger.warning("Username not provided in request data")
                    return JsonResponse({'error': "Username is required for login."}, status=status.HTTP_400_BAD_REQUEST)
                
                email = None
                try:  
                    if "@" in username:
                        user = get_user_model().objects.get(email=username)
                        username = user.username
                        email = user.email
                    else:
                        user = get_user_model().objects.get(username=username)
                        email = user.email
                except User.DoesNotExist:
                    logger.warning("No user found for username/email: %s", username)
                    return JsonResponse({'error': 'Incorrect user'}, status=status.HTTP_403_FORBIDDEN)

                # Compare CN with username for validation
                if client_cn != username:
                    logger.error("Mismatch between client CN and provided username")
                    return JsonResponse({'error': 'Incorrect user or certificate'}, status=status.HTTP_403_FORBIDDEN)
                
                # Attach username and email to the request object
                request.username = username
                request.email = email
               
            # Handle token refresh path - validate client CN and access token's user
            elif path in [ "refresh","logout","availableServers","session","logoutSession","updateSession","send"]:
                logger.debug("Processing /refresh or /logout or /availableServers or /session etc. path")
                
                response = self.veryfy_request(request)
                if response:
                    return response
                
                try:
                    auth_header = request.headers.get('Authorization', '')

                    if auth_header.startswith('Bearer '):
                        access_token = auth_header.split('Bearer ')[1] 
                        logger.debug(f"access_token :  {access_token}")
                    if not access_token:
                        logger.error("No access token provided in request for refresh")
                        return JsonResponse({'error': 'No access token provided in request for refresh'}, status=status.HTTP_401_UNAUTHORIZED)
                except :
                    logger.error("No access token provided in request for refresh")
                    return JsonResponse({'error': 'No valid Access token'}, status=status.HTTP_401_UNAUTHORIZED)

                # Retrieve the access token object
                access_token_obj = AccessToken.objects.filter(token=access_token).first()
                if not access_token_obj:
                    logger.error("Access token not found in database")
                    return JsonResponse({'error': 'No valid Access token'}, status=status.HTTP_401_UNAUTHORIZED)
                
                user = access_token_obj.user
                if user:
                    logger.debug(f"User associated with token: {user.username}")
                    if client_cn != user.username:
                        logger.error("Mismatch between client CN and token user")
                        return JsonResponse({'error': 'Incorrect user or certificate'}, status=status.HTTP_403_FORBIDDEN)
                else:
                    logger.error("Access token has no associated user")
                    return JsonResponse({'error': 'No valid Access token'}, status=status.HTTP_401_UNAUTHORIZED)
            elif path in [ "qrcode","qrlink"]:
                if 'text/html' not in request.META.get('HTTP_ACCEPT', ''):
                    return JsonResponse({'error': 'No valid Request'}, status=status.HTTP_406_NOT_ACCEPTABLE)
                    
            elif path == "admin":
                if 'text/html' not in request.META.get('HTTP_ACCEPT', ''):
                    return JsonResponse({'error': 'No valid Request'}, status=status.HTTP_406_NOT_ACCEPTABLE)
                
                admin = request.META.get('SSL_CLIENT_SAN_DNS_0')
                logger.debug(f"{admin}")
                if admin != "admin":
                    logger.debug("Certificate not appropriate")
                    return formatted_response(
                                    request, 
                                    {'error': 'Certificate not appropriate'},
                                    template_name='error.html',
                                    status_code=status.HTTP_401_UNAUTHORIZED)

                user = get_user_model().objects.get(username=client_cn)                
                
                if not user.is_superuser or  not user.is_active:  
                    logger.debug("user has no permissions")
                    return formatted_response(
                                    request, 
                                    {'error': 'User has no permissions'},
                                    template_name='error.html',
                                    status_code=status.HTTP_401_UNAUTHORIZED)

                logger.debug("certificate correct for user")
            
            else:
                logger.debug(f"incorrect path: {path}")
                return formatted_response(
                                    request, 
                                    {'error': 'not a valid path'},
                                    template_name='error.html',
                                    status_code=status.HTTP_404_NOT_FOUND) 
        return self.get_response(request)