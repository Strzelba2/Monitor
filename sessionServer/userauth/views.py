from django.contrib.auth import authenticate, logout , login
from django.views.decorators.debug import sensitive_post_parameters
from django.db import transaction
from django.utils.decorators import method_decorator
from oauth2_provider.models import AccessToken, Application, RefreshToken
from oauth2_provider.views import TokenView, RevokeTokenView
from oauth2_provider.contrib.rest_framework import TokenHasReadWriteScope
from rest_framework import views, status
from rest_framework.response import Response
from rest_framework.throttling import UserRateThrottle
from rest_framework.permissions import IsAuthenticated,AllowAny,IsAdminUser
from rest_framework.renderers import JSONRenderer, TemplateHTMLRenderer
from session.password_mask_filter import PasswordMaskFilter
from .exceptions import SecretServerError
from django.conf import settings
from django.core.cache import cache
from django.contrib.sessions.models import Session
from oauthlib.common import generate_token
from django.core.signing import TimestampSigner, BadSignature, SignatureExpired
from django.utils.timezone import now
from datetime import timedelta
from oauth2_provider.settings import oauth2_settings
import pyotp
from .models import User, UsedToken
from session.models import Session as ServerSession, Server
from .two_factor import TwoFactor
from django.core.mail import send_mail
from django.urls import reverse
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from .validators import validate_signed_token_format
from django.core.exceptions import ValidationError

import logging
from requests.exceptions import SSLError
import requests
import traceback
import json
from typing import Dict

from utils.responses import formatted_response

logger = logging.getLogger('django')
logger.addFilter(PasswordMaskFilter())


@method_decorator(sensitive_post_parameters("password"), name='dispatch')
class LoginAPIView(views.APIView,TokenView):
    """
    API view for handling user login, authentication, and OAuth2 token generation.
    
    Features:
    - Handles user authentication using username and password.
    - Supports session management and invalidation of old sessions.
    - Implements rate limiting to prevent brute-force attacks.
    - Integrates with an external secret server for client secret decryption.
    """
    throttle_classes = [UserRateThrottle]
    permission_classes = [AllowAny] 
    renderer_classes = [JSONRenderer]
    
    def dispatch(self, request, *args, **kwargs):
        logger.debug("dispatch")
        
        # Access username and email set by the middleware
        username = getattr(request, 'username', None)
        email = getattr(request, 'email', None)
        logger.debug(f"email: {email}")
        logger.debug(f"username: {username}")

        verification_code = request.headers.get('X-Verification-Code')
        secret_key = TwoFactor.generate_secret_key(email, username)
        logger.debug(f"secretKey: {secret_key}")
        logger.debug(f"verification_code: {verification_code}")
        totp = pyotp.TOTP(secret_key)

        if not verification_code or not totp.verify(verification_code, valid_window=1):
            return formatted_response(
                request,
                {'error': 'Invalid or expired code'},
                template_name='error.html',
                status_code=status.HTTP_403_FORBIDDEN
            )

        return super().dispatch(request, *args, **kwargs)

    def create_response(self, token: AccessToken,refresh_token: RefreshToken ) -> Dict[str, str]:
        """
        Create a response dictionary containing details of the access and refresh tokens.
        
        Args:
            token (AccessToken): The access token instance containing token and scope information.
            refresh_token (RefreshToken): The refresh token instance linked to the user.

        Returns:
            Dict[str, str]: A dictionary containing the access token, refresh token, 
                            expiry duration, token type, and scope.
        """
        logger.debug("Creating response data for access and refresh tokens.")
        logger.debug("Access token: %s", token.token)
        logger.debug("Refresh token: %s", refresh_token.token)
        logger.debug("Access token scope: %s", token.scope)
        logger.debug("Access token expiration: %s seconds", oauth2_settings.ACCESS_TOKEN_EXPIRE_SECONDS)

        # Construct the response data
        response_data = {
            'access_token': token.token,
            'expires_in': oauth2_settings.ACCESS_TOKEN_EXPIRE_SECONDS,
            'token_type': 'Bearer',
            'scope': token.scope,
            'refresh_token': refresh_token.token,
        }
        logger.info("Response data created successfully.")
        return response_data
    
    def logout_old_sessions(self, user: object, request) -> None:
        """
        Logout old user sessions except the current one.
        
        :param user: Authenticated user instance.
        :param current_session_key: Current session key to retain.
        """
        Session.objects.filter(session_data__contains=user.pk).exclude(
                session_key=request.session.session_key
            ).delete()
                        

    @classmethod
    def get_decrypted_secret(self, username: str, hashed_secret: str) -> str:
        """
        Fetch the decrypted secret from the secret server to verify the client credentials.
        
        :param username: Username for the secret server request
        :param hashed_secret: Hashed secret (client_secret) for the secret server request
        :raises SecretServerError: If there's an SSL or Timeout error
        :returns: Decrypted secret as a string if successful
        """
        
        url = f"{settings.SECRET_SERVER_URL}/verify_and_return_secret/"
        session = requests.Session()
        payload = {"username": username,"hashed_secret": hashed_secret}

        try:
            logger.debug(f"Requesting secret server for user: {username}")

            session.cert = (settings.SECRET_CERT_PATH, settings.SECRET_KEY_PATH)
            session.verify = settings.CA_CERT_PATH
            response = session.post(url, json=payload, timeout=10)
            
        except SSLError as e:
            logger.error(f"SSL error while requesting secret: {e}")
            raise SecretServerError(Response(
                {'error': f'SSL Error: {e} - {traceback.format_exc()}'},
                status=status.HTTP_401_UNAUTHORIZED
            ))
        except TimeoutError:
            logger.error("Timeout error while requesting secret")
            raise SecretServerError(Response(
                {'error': 'time expired to confirm try again'},
                status=status.HTTP_408_REQUEST_TIMEOUT
            ))
        except requests.exceptions.RequestException as e:
            logger.error(f"An unexpected error occurred: {e}")
            raise SecretServerError(Response(
                {'error': 'An unexpected error occurred, please try again'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            ))
            
            
        if response.status_code == 200:
            logger.debug("Secret server request successful")
            return response.json().get("secret")
        else:
            logger.error(f"Failed to retrieve secret: {response.status_code}, {response.text}")
            raise Exception(f"Failed to retrieve secret: {response.status_code} - {response.text}")
    
    def post(self, request, *args, **kwargs) -> Response:
        """
        Handle user login, enforce rate limiting, and generate an OAuth2 access token.
        
        :param request: Django REST Framework request object
        :returns: JSON response with either token data or an error message
        """
        
        logger.debug(f"POST Login request received with parameters: {request.data}")
        
        # Ensure data contains only expected parameters
        if len(list(request.data.values())) > 2:
            logger.warning("Excessive parameters in login request")
            return Response({'error': 'Incorrect data'}, status=status.HTTP_400_BAD_REQUEST)

        username = request.data.get('username')
        password = request.data.get('password')
        
        if not username or not password:
            logger.warning("Missing username or password in login request")
            return Response({'error': 'Missing credentials'}, status=status.HTTP_400_BAD_REQUEST)
        
        # Throttle login attempts per user
        login_attempts_key = f"login_attempts_{username}"
        login_attempts = cache.get(login_attempts_key, 0)
        logger.debug(f"login_attempts: {login_attempts}  for key: {login_attempts_key}")
        if login_attempts >= 3:
            logger.warning(f"Too many login attempts for user: {username}")
            return Response({'error': 'Too many login attempts. Try again later.'}, status=status.HTTP_429_TOO_MANY_REQUESTS)
   
        # Authenticate the user with provided credentials
        user = authenticate(username=username, password=password)
        if user is None:
            cache.set(login_attempts_key, login_attempts + 1, timeout=settings.CACHE_TIMEOUT)
            logger.error("Invalid login credentials")
            return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)
        
        else:
            if user is not None:
                if request.session.session_key:
                    logger.info(f" login with session_key {request.session.session_key}")
                    self.logout_old_sessions(user,request)
                    login(request, user)
                    logger.info("Logged in successfully")
                else:
                    logger.info("first login")
                    user_lock_key = f"login_lock:{request.user.id}"
                    if cache.get(user_lock_key):
                        return Response({'error': 'Someone is already in the process of logging in'}, status=401)
                    
                    cache.set(user_lock_key, "locked", 5)
                    
                    login(request, user)
                    cache.delete(user_lock_key)
                

        # Reset login attempts on successful login
        cache.delete(login_attempts_key)
        
        # Remove any previous access tokens for this user
        existing_token = AccessToken.objects.filter(user=user).first()
        if existing_token:
            logger.info(f"Access token {existing_token.token} exist for  user {user.username}")
            refresh_token = RefreshToken.objects.filter(access_token=existing_token).first()
            if refresh_token:
                logger.info(f"RefreshToken {refresh_token.token} exist for  user {user.username}")
                existing_token.token = generate_token()
                existing_token.expires = now() + timedelta(seconds=oauth2_settings.ACCESS_TOKEN_EXPIRE_SECONDS)
                existing_token.save()
                
                return Response(self.create_response(existing_token,refresh_token), status=status.HTTP_200_OK)
            else:
                AccessToken.objects.filter(user=user).delete()
                return Response({'error': 'Invalid Access Token'}, status=status.HTTP_401_UNAUTHORIZED)
                

        # Retrieve application tied to the user for token generation
        try:
            application = Application.objects.get(user=user)    
        except Application.DoesNotExist:
            logger.error("No application found for user")
            return Response({'error': 'Application for user not found'}, status=status.HTTP_400_BAD_REQUEST)

        # Prepare request data for token generation
        request_data = request.data.copy()
        request_data['grant_type'] = 'password'
        request_data['client_id'] = application.client_id

        # Decrypt client secret
        try:
            request_data['client_secret'] = LoginAPIView.get_decrypted_secret(user.username, application.client_secret)
   
        except SecretServerError as e:
            logger.error("Error in retrieving secret for application client")
            return e.response  
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            return Response({'error':str(e)}, status=status.HTTP_401_UNAUTHORIZED)

        # Replace the original request POST data with modified request data
        request._request.POST = request_data
        logger.info(f"request_data: {request_data}")
        

        # Generate the OAuth2 token response
        try:
            url, headers, body, statusReq = self.create_token_response(request._request)
        except ValueError as e:
            return Response({'error':str(e)}, status=status.HTTP_401_UNAUTHORIZED)
        
        logger.info("Token generation successful")
        return Response(json.loads(body), status=statusReq, headers=headers)

@method_decorator(sensitive_post_parameters('password', 'refresh_token'), name='dispatch')    
class CustomRefreshTokenView(views.APIView,TokenView):
    """
    API view for refreshing access tokens using a valid refresh token. 
    Handles token verification, application validation, and token regeneration.

    Features:
    - Supports rate-limiting to prevent abuse.
    - Ensures sensitive data like passwords and refresh tokens are handled securely.
    - Provides detailed error responses for invalid or expired tokens.
    """
    permission_classes = [IsAuthenticated, TokenHasReadWriteScope]
    throttle_classes = [UserRateThrottle]
    renderer_classes = [JSONRenderer]

    def post(self, request, *args, **kwargs) -> Response:
        """
        Handle the POST request to refresh the access token.

        :param request: DRF Request object containing the refresh token and client credentials.
        :param args: Additional positional arguments.
        :param kwargs: Additional keyword arguments.
        :returns: Response object with a new access token or an error message.
        """
        logger.debug(f"POST Refresh token request received with parameters{request.data}")
        
        # Extract the refresh token from the request data
        refresh_token = request.data.get('refresh_token')
        if not refresh_token :
            logger.warning("No refresh token provided in the request.")
            return Response({'error': 'Missing credentials'}, status=status.HTTP_400_BAD_REQUEST)
        
        # Verify the refresh token
        try:
            refresh_token = RefreshToken.objects.get(token=refresh_token)
            user = refresh_token.user
            logger.debug(f"Valid refresh token found for user: {user.username}")
        except RefreshToken.DoesNotExist:
            logger.error("Invalid refresh token provided.")
            return Response({'error': 'Invalid refresh token'}, status=status.HTTP_400_BAD_REQUEST)
        except RefreshToken.MultipleObjectsReturned:
            logger.warning("Multiple refresh tokens found; cleaning up.")
            for refresh_token in RefreshToken.objects.filter(token=refresh_token):
                if refresh_token.access_token:
                    refresh_token.access_token.delete()
                    refresh_token.delete()
                else:
                    refresh_token.delete()
            return Response({'error': 'Duplicate refresh tokens found and removed.'}, status=status.HTTP_400_BAD_REQUEST)
        
        # Check if the refresh token has expired or is invalid
        try:
            if not refresh_token.access_token or refresh_token.access_token.expires < now():
                logger.error("Refresh token has expired.")
                return Response({'error': 'Refresh token has expired'}, status=status.HTTP_400_BAD_REQUEST)
        except AttributeError:
            logger.error("Invalid token configuration detected.")
            return Response({'error': 'Invalid token configuration'}, status=status.HTTP_400_BAD_REQUEST)

        # Retrieve the associated application
        try:
            application = Application.objects.get(user=user)
            logger.debug(f"Application found for user: {user.username}")
        except Application.DoesNotExist:
            logger.debug("No application associated with the user.")
            return Response({'error': 'Invalid client credentials'}, status=status.HTTP_400_BAD_REQUEST)

        # Prepare request data for token generation
        request_data = request.data.copy()
        request_data['grant_type'] = 'refresh_token'
        request_data['client_id'] = application.client_id
        
        # Decrypt client secret
        try:
            request_data['client_secret'] = LoginAPIView.get_decrypted_secret(user.username, application.client_secret)
            logger.debug("Client secret retrieved successfully.")    
        except SecretServerError as e:
            logger.error("Error in retrieving secret for application client")
            return e.response  
        except Exception as e:
            logger.error(f"Unexpected error while decrypting client secret: {str(e)}")
            return Response({'error':str(e)}, status=status.HTTP_401_UNAUTHORIZED)
        
        # Update the original request with modified data
        request._request.POST = request_data
        
        # Pass the request to the parent TokenView for token regeneration
        response = super().post(request._request, *args, **kwargs)
        logger.info(f"Token refresh successful for user: {user.username}")
        return response


class LogoutAPIView(views.APIView,RevokeTokenView):
    """
    API view for handling user logout and token revocation.
    Extends RevokeTokenView to support OAuth2 token revocation.
    """
    permission_classes = [IsAuthenticated, TokenHasReadWriteScope]
    
    
    def logout_user_if_lack_access_token(self,request,access_token,response):
        """
        Handles logout and cleanup when the access token is missing.
        If an orphaned refresh token is found, it will be deleted.

        Args:
            request: The HTTP request object containing user information.
            access_token: The access token object to check.
            response: The response object from the token revocation attempt.

        Returns:
            A Response object indicating the result of the logout operation.
        """
        logger.info("Checking if access token exists for logout.")
        access_token_obj = AccessToken.objects.filter(token=access_token.token).first()
                    
        if not access_token_obj:
            logger.warning("Access token not found. Proceeding with session logout and cleanup.")
            if request.user.is_authenticated:
                # Clear the user session
                logout(request)
                logger.info("User session cleared successfully.")
                
                # Find and delete orphaned refresh tokens
                orphaned_refresh_tokens = RefreshToken.objects.filter(access_token__isnull=True)
                if orphaned_refresh_tokens.exists():
                    orphaned_refresh_tokens.delete()
                    logger.info("Orphaned refresh tokens deleted.")
                    
            # Return a successful logout response   
            response = Response({"message": "Successfully logged out"}, status=status.HTTP_200_OK)
            return response
        else:
            logger.debug("Access token found; no cleanup actions required.")
            return response   
         
    def post(self, request, *args, **kwargs):
        """
        Handle POST request for logging out the user and revoking tokens.
        Calls the parent RevokeTokenView for token revocation and handles cleanup.

        Args:
            request: The HTTP request object containing the user's access token and application details.
            *args: Additional positional arguments.
            **kwargs: Additional keyword arguments.

        Returns:
            A Response object indicating the result of the logout operation or an error.
        """
        logger.info("Starting logout process for user.")
        access_token = request.auth  
        
        if access_token:
            try:
                if request.user.is_authenticated:
                    username = request.user.username
                    logger.debug(f"Authenticated user: {username}")
                else:
                    Response({'error': 'User is not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)
                    
                try:
                    application = Application.objects.get(user=request.user)  
                    logger.debug(f"Application found for user: {application.client_id}")  
                except Application.DoesNotExist:
                    logger.error("No application found for user")
                    return Response({'error': 'Application for user not found'}, status=status.HTTP_400_BAD_REQUEST)
                
                with transaction.atomic(): 
                    existing_session = ServerSession.objects.filter(user=request.user).first()
                    
                    if existing_session:
                        existing_session.delete()
                        logger.debug("the existing session has been deleted")

                    server = Server.objects.filter(user=request.user).first()
                    if server:
                        if server:
                            server.available = True
                            server.user = None
                            server.save()
                
                request_data = request.POST.copy()
                request_data['token'] = access_token.token
                request_data['client_id'] = application.client_id

                # Decrypt client secret
                try:
                    request_data['client_secret'] = LoginAPIView.get_decrypted_secret(username, application.client_secret)
                    logger.debug("Client secret retrieved successfully.")
                    
                except SecretServerError as e:
                    logger.error("Error in retrieving secret for application client")
                    return e.response  
                except Exception as e:
                    logger.error(f"Unexpected error: {str(e)}")
                    return Response({'error':str(e)}, status=status.HTTP_401_UNAUTHORIZED)
                
                request._request.POST = request_data
                
                # Attempt to revoke the token using RevokeTokenView's post method
                logger.info("Revoking access token via RevokeTokenView.")
                response = super().post(request._request, *args, **kwargs)
                
                # If revocation was successful, proceed with user session logout
                if response.status_code == 200:
                    logger.info("Token revocation successful. Clearing user session.")
                    if request.user.is_authenticated:
                        logout(request)
                        logger.info("User session cleared.")
                        
                    response = Response({"message": "Successfully logged out"}, status=status.HTTP_200_OK)
                    return response
                else:
                    logger.warning("Token revocation unsuccessful; checking access token presence.")
                    return self.logout_user_if_lack_access_token(request,access_token,response)
            except Exception as e:
                # Handle any exceptions during revocation
                logger.error(f"Exception during token revocation: {str(e)}")
                response = Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
                return self.logout_user_if_lack_access_token(request,access_token,response)
            
        else:
            logger.error("No access token found in request. Unable to proceed with logout.")
            return Response({'error': 'Access token missing from request'}, status=status.HTTP_400_BAD_REQUEST)

class QRCodeView(views.APIView):
    """
    View to generate and display a QR code for two-factor authentication.

    This view handles:
    - Validating the signed token.
    - Checking for expired or used tokens.
    - Generating a QR code based on a valid token.

    Methods:
        - `get`: Handles GET requests to process the token and return the QR code.
    """
    
    permission_classes = [] 
    renderer_classes = [TemplateHTMLRenderer] 

    def get(self, request, token):
        """
        Handle GET requests to validate the token and generate a QR code.

        Args:
            request (HttpRequest): The incoming HTTP request.
            token (str): The signed token to validate.

        Returns:
            HttpResponse: A response containing the QR code image or an error message.

        Raises:
            ValidationError: If the token format is invalid.
        """
        
        logger.info("Starting qrcode view process for user.")

        signer = TimestampSigner(salt=settings.SERVER_SALT)
  
        if not token :
            logger.warning("Request missing token.")
            return formatted_response(
                request,
                {'error': 'Invalid request'},
                template_name='error.html',
                status_code=status.HTTP_400_BAD_REQUEST
            )
        
        # Check if the token exists and is already used
        if UsedToken.objects.filter(token=token).exists():
            logger.warning("Token has already been used.")
            return formatted_response(
                            request, 
                            {'error': 'This link has already been used.'},
                            template_name='error.html',
                            status_code=status.HTTP_403_FORBIDDEN)

        # Validate token format
        try:
            validate_signed_token_format(token, min_length=20, max_length=255)
        except ValidationError as e:
            logger.error(f"Token format validation failed: {str(e)}")
            return formatted_response(
                request,
                {'error': 'Invalid token format'},
                template_name='error.html',
                status_code=status.HTTP_400_BAD_REQUEST
            )
          
        # Unsigned token and validate timeout  
        try:
            user_id = signer.unsign(token, max_age=settings.TOKEN_TIMEOUT)
        except SignatureExpired:
            logger.warning("Token has expired.")
            return formatted_response(
                            request, 
                            {'error': 'Link has expired'},
                            template_name='error.html',
                            status_code=status.HTTP_404_NOT_FOUND)
           
        except BadSignature:
            logger.error("Token has an invalid signature.")
            return formatted_response(
                            request, 
                            {'error': 'Invalid token'},
                            template_name='error.html',
                            status_code=status.HTTP_404_NOT_FOUND)

        # Retrieve user from token data
        user = User.objects.filter(id=user_id).first()
        if not user:
            logger.error(f"No user found with ID: {user_id}")
            return formatted_response(
                request,
                {'error': 'User does not exist'},
                template_name='error.html',
                status_code=status.HTTP_404_NOT_FOUND
            )

        # Mark token as used
        logger.info(f"Marking token as used for user: {user.username}")
        UsedToken.objects.create(token=token, user=user)

        # Generate QR code
        secret_key = TwoFactor.generate_secret_key(email=user.email, username=user.username)
        provisioning_uri = TwoFactor.generate_provisioning_uri(secret_key, username=user.username)
        qr_code_image = TwoFactor.generate_qr_code(provisioning_uri)

        logger.info(f"QR code successfully generated for user: {user.username}")
        return Response({'image': qr_code_image}, template_name='qrcode.html')
    
class SendQRLinkView(views.APIView):
    """
    View to generate and send a QR code link for further registration.
    Only accessible by admin users.
    """
    permission_classes = [IsAdminUser]
    renderer_classes = [TemplateHTMLRenderer] 
    
    def http_method_not_allowed(self, request, *args, **kwargs):
        return formatted_response(
            request,
            {'error': 'Invalid method'},
            template_name='error.html',
            status_code=status.HTTP_405_METHOD_NOT_ALLOWED
        )
    
    def generate_secure_link(self, user_id: int) -> str:
        """
        Generate a secure signed link for the user.

        Args:
            user_id (int): The ID of the user.

        Returns:
            str: A full URL containing the secure token.
        """
        
        signer = TimestampSigner(salt=settings.SERVER_SALT)
        token = signer.sign(user_id)
        
        validate_signed_token_format(token, min_length=20, max_length=255)
        
        logger.info(f"Generated secure token for user {user_id}.")
        domain = settings.DOMAIN
        path = reverse('qrcode',kwargs={'token': token}) 

        return f"https://{domain}{path}"
    
    def send_email(self,user: User, link: str) -> None:
        """
        Send an email with the QR code link to the user.

        Args:
            user (User): The recipient user.
            link (str): The secure link to include in the email.
        """
        logger.info(f"Preparing email for user {user.email}.")
        
        subject = f"QrCode for {user.username} for further registration"
        from_email = settings.DEFAULT_FROM_EMAIL
        recipient_list = [user.email]
        context = {
            "user": user,
            "link": link,
        }
        html_email = render_to_string("qr_email.html", context)
        text_email = strip_tags(html_email)

        email = EmailMultiAlternatives(subject, text_email, from_email, recipient_list)
        email.attach_alternative(html_email, "text/html")
        email.send()
        logger.info(f"Email successfully sent to {user.email}.")

    def get(self, request, user_id: str, *args, **kwargs) -> Response:
        """
        Handle GET requests to generate and send a QR code link.

        Args:
            request (HttpRequest): The incoming request.
            user_id (str): The user ID passed in the URL.

        Returns:
            Response: Success or error response.
        """
  
        try:
            # Validate user ID format
            if not str(user_id).isdigit():
                logger.warning("Invalid user ID format received.")
                return formatted_response(
                    request,
                    {'error': 'Invalid user ID'},
                    template_name='error.html',
                    status_code=status.HTTP_400_BAD_REQUEST
                )  
            user = User.objects.filter(id=user_id).first()

            if not user:
                logger.warning(f"User with ID {user_id} does not exist.")
                return formatted_response(
                    request,
                    {'error': 'User does not exist'},
                    template_name='error.html',
                    status_code=status.HTTP_404_NOT_FOUND
                )
            try:
                link = self.generate_secure_link(user_id=user.id)
            except Exception as e:
                return formatted_response(
                    request,
                    {'error': str(e)},
                    template_name='error.html',
                    status_code=status.HTTP_400_BAD_REQUEST
                )    
            self.send_email(user,link)

            return Response({'message': f"The link was sent to user {user.email}."}, template_name='success.html')
        
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}", exc_info=True)
            return formatted_response(
                            request, 
                            {'error': str(e)},
                            template_name='error.html',
                            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
