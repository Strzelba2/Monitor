from django.utils import timezone
from django.shortcuts import get_object_or_404
from django.db import transaction
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from oauth2_provider.contrib.rest_framework import TokenHasReadWriteScope
from rest_framework import views, status
from rest_framework.response import Response
from rest_framework.throttling import UserRateThrottle
from rest_framework.permissions import IsAuthenticated,AllowAny
from rest_framework.exceptions import ValidationError
from .models import Server,Session,TemporaryToken
from .hmac_token import HmacToken
from .serializers import (
    ServerSerializer,
    ServerAvailabilitySerializer,
    SessionIdSerializer,
    GenerateSessionSerializer,
    GeneratetokenSerializer,
    VerifySessionSerializer,
    UpdateSessionSerializer
)
from rest_framework.filters import SearchFilter
from .authentication import IPWhitelistAuthentication
from django.conf import settings
import base64
import logging

logger = logging.getLogger(__name__)

 
class AvailableServersView(views.APIView):
    """
    API view to retrieve a list of available servers based on search criteria.
    """
    permission_classes = [IsAuthenticated, TokenHasReadWriteScope]
    throttle_classes = [UserRateThrottle]
    search_fields = ['name', 'location']

    def get(self, request) -> Response:
        """
        Handles GET requests to fetch available servers based on search criteria.
        
        Args:
            request (Request): The request object containing query parameters.
        
        Returns:
            Response: JSON response with filtered server data or error message.
        """
        logger.info("Fetching available servers.")
        try:
            servers = Server.objects.filter(available=True)
            
            search_param = request.query_params.get('search', '')
            
            if not search_param:
                logger.warning("Search query parameter is missing.")
                return Response({"error": "Request should include search query "}, status=status.HTTP_400_BAD_REQUEST)

            filter_backend = SearchFilter()
            filtered_servers = filter_backend.filter_queryset(request, servers, self)

            serializer = ServerSerializer(filtered_servers, many=True)
            
            logger.info("Successfully retrieved available servers.")
            return Response(serializer.data, status=status.HTTP_200_OK)
        
        except Exception as e:
            logger.error(f"unexpected exception : {e}")
            return Response({"error":"unexpected exception"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
    
class GenerateSessionView(views.APIView):
    """
    API view to generate a session for a user on a specified server.
    """
    permission_classes = [IsAuthenticated, TokenHasReadWriteScope]
    throttle_classes = [UserRateThrottle]

    def post(self, request) -> Response:
        """
        Handles POST requests to create a session for the authenticated user.
        
        Args:
            request (Request): The request object containing session details.
        
        Returns:
            Response: JSON response with session details or error message.
        """
        logger.info("Generating session.")
        serializer = GenerateSessionSerializer(data=request.data)
        if not serializer.is_valid():
            logger.warning("Invalid session data provided.")
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        user = request.user
        server_name = serializer.validated_data['server_name']

        try:
            server = Server.objects.get(name=server_name)
        except Server.DoesNotExist:
            logger.warning(f"Server with name {server_name} not found.")
            return Response({'error': f'Server with name {server_name} not found'}, status=status.HTTP_404_NOT_FOUND)

        if server.user :
            logger.warning(f"Server {server_name} is already in use.")
            return Response({'error': f'Server with name {server_name} is not available'}, status=status.HTTP_403_FORBIDDEN)
        
        # Check for existing active session
        existing_session = Session.objects.filter(user=user, server=server, expires__gt=timezone.now()).first()


        if existing_session:
            logger.info("Returning existing session.")
            serializer = SessionIdSerializer(existing_session)
            return Response(serializer.data, status=status.HTTP_200_OK)

        try:
            new_session = Session.objects.create(user=user, server=server)
            logger.info("New session created successfully.")
        except Exception as e:
            logger.error(f"Failed to create session: {e}")
            return Response({'error': f'Failed to create session: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        serializer = SessionIdSerializer(new_session)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
class UpdateSessionView(views.APIView):
    """
    API view to update an existing session.
    """
    permission_classes = [IsAuthenticated, TokenHasReadWriteScope]
    throttle_classes = [UserRateThrottle]
    
    def post(self, request) -> Response:
        """
        Handles POST requests to update a session.
        
        Args:
            request (Request): The request object containing session update details.
        
        Returns:
            Response: JSON response with updated session details or error message.
        """
        logger.info("Updating session.")
        serializer = UpdateSessionSerializer(data=request.data)
        if not serializer.is_valid():
            logger.warning("Invalid session update data provided.")
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        session_id = serializer.validated_data['session_id']
        
        existing_session = Session.objects.filter(sessionId=session_id, expires__gt=timezone.now()).first()
        
        if not existing_session:
            logger.warning(f"Session {session_id} is not valid.")
            return Response({'error': f'Session {session_id} is not Valid'}, status=status.HTTP_403_FORBIDDEN)
        
        if existing_session.user != request.user:
            existing_session.delete()
            logger.warning("Invalid user for session.")
            return Response({'error': 'Invalid user for session'}, status=status.HTTP_403_FORBIDDEN)
        
        server = Server.objects.filter(user=request.user).first()
        if server:
            if server != existing_session.server:
                server.delete()
                existing_session.server.delete()
                existing_session.delete()
                logger.warning("Server mismatch for session.")
                return Response({'error': 'Server mismatch for session'}, status=status.HTTP_403_FORBIDDEN)
        else:
            existing_session.server.delete()
            existing_session.delete()
            logger.warning("Server does not exist for session.")
            return Response({'error': 'Server do not exist for session'}, status=status.HTTP_403_FORBIDDEN)
        
        try:
            existing_session.delete()
            logger.info("Session updated successfully.")
            new_session = Session.objects.create(user=request.user, server=existing_session.server)
            
        except Exception as e:
            logger.error(f"Failed to update session: {e}")
            return Response({'error': f'Failed to create session: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        serializer = SessionIdSerializer(new_session)
        return Response(serializer.data, status=status.HTTP_200_OK)  
    
class LogoutSessionView(views.APIView):
    """
    API view to handle user session logout.
    
    This endpoint validates the session ID, checks ownership, verifies the associated server,
    and deletes the session while updating the server state accordingly.
    """
    permission_classes = [IsAuthenticated, TokenHasReadWriteScope]
    throttle_classes = [UserRateThrottle]
    
    def post(self, request) -> Response:
        """
        Handle session logout request.
        
        Args:
            request (Request): The HTTP request containing session ID data.
        
        Returns:
            Response: A success message or an error response with appropriate HTTP status code.
        """
        logger.info(f"Received logout session request for user: {request.user}" )
        
        serializer = UpdateSessionSerializer(data=request.data)
        if not serializer.is_valid():
            logger.warning(f"Invalid session logout request: {serializer.errors}")
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        session_id = serializer.validated_data['session_id']
        
        with transaction.atomic(): 
            existing_session = Session.objects.filter(sessionId=session_id, expires__gt=timezone.now()).first()
            
            if not existing_session:
                logger.warning(f"Session {session_id} does not exist or is expired" )
                return Response({'error': f'Session {session_id} do not exist'}, status=status.HTTP_404_NOT_FOUND)
            
            if existing_session.user != request.user:
                logger.warning(f"User {request.user} attempted to delete session {session_id} belonging to another user")
                existing_session.delete()
                return Response({'error': 'Invalid user for session'}, status=status.HTTP_403_FORBIDDEN)
            
            server = Server.objects.filter(user=request.user).first()
            if server:
                if server != existing_session.server:
                    logger.error(f"Server mismatch detected for session {session_id}")
                    server.delete()
                    existing_session.server.delete()
                    existing_session.delete()
                    return Response({'error': 'Server mismatch for session'}, status=status.HTTP_403_FORBIDDEN)
            else:
                logger.error(f"No server found for user {request.user}")
                existing_session.delete()
                return Response({'message': 'Server is waiting for a connection'}, status=status.HTTP_200_OK)
            
            try:
                server = existing_session.server
                server.available = True
                server.user = None
                server.save()
                existing_session.delete()
                logger.info(f"Successfully logged out session {session_id}")
            except Exception as e:
                logger.error(f"Failed to logout session {session_id}: {str(e)}")
                return Response({'error': f'Failed to create session: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response({'message': 'Logout session sucessful'}, status=status.HTTP_200_OK) 
    
class Generatetoken(views.APIView):
    """
    API view to generate a temporary authentication token for a user session.
    
    The token is signed using HMAC and includes session details, IP address, 
    request method, and encoded body.
    """
    permission_classes = [IsAuthenticated, TokenHasReadWriteScope]
    throttle_classes = [UserRateThrottle]

    def post(self, request) -> Response:
        """
        Handles POST requests to generate a temporary token.
        
        Args:
            request (Request): The HTTP request object containing user and session details.

        Returns:
            Response: JSON response containing the generated token or an error message.
        """
        user = request.user
        
        ip_address = request.META.get('HTTP_X_FORWARDED_FOR')
        
        if ip_address:
            ip_address = ip_address.split(',')[0]
        else:
            ip_address = request.META.get('REMOTE_ADDR')
            
        logger.info(f"Generating token for user: {user.username} from IP: {ip_address}")
        
        serializer = GeneratetokenSerializer(data=request.data)
        if not serializer.is_valid():
            logger.warning("Invalid token request data")
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        server_name = serializer.validated_data['server_name']
        method = serializer.validated_data['method']
        encode_body = serializer.validated_data['encode_body']
        path = serializer.validated_data['path']

        server = get_object_or_404(Server, name=server_name)
        session = Session.objects.filter(user=user, server=server, expires__gt=timezone.now()).first()
        
        if not session:
            logger.error("Session validation failed: No active session found")
            return Response({'error': 'Session could not be validated'}, status=status.HTTP_404_NOT_FOUND)
        
        logger.info(f"time:{timezone.now()}")
        try:
            token = TemporaryToken.objects.create(session=session,path=path)
            logger.info(f"Temporary token created for session: {session.sessionId}")
        except Exception as e:
            logger.exception("Failed to create TemporaryToken")
            return Response({'error': f'Failed to create TemporaryToken: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
         
        message = f"{session.sessionId}{server.ip_address}{ip_address}{method}{token.created_at}{session.user.username}{encode_body}"
        logger.debug(f"token:{token}")
        logger.debug(f"message:{message}")
        encoded_hmac_signature = HmacToken.calculate_token(token,message)
        
        logger.debug(f"Generated HMAC token: {encoded_hmac_signature}")
        return Response({'token': encoded_hmac_signature }, status=status.HTTP_200_OK)
    
class VerifySessionView(views.APIView):
    """
    API view to verify a session using an HMAC-signed authorization header.
    """
    authentication_classes = [IPWhitelistAuthentication]  
    permission_classes = [AllowAny]
    throttle_classes = [UserRateThrottle]
    
    @csrf_exempt
    def post(self, request, server_name: str) -> Response:
        """
        Verifies an HMAC-signed session authorization.
        
        Args:
            request (Request): HTTP request with authorization data.
            server_name (str): The name of the server to validate the session against.
        
        Returns:
            Response: Success or error response.
        """
        logger.info(f"Verification session  for {server_name}")
        serializer = VerifySessionSerializer(data=request.data)
        if not serializer.is_valid():
            logger.warning("invalid data for request")
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            session_id, hmac, timestamp = serializer.validated_data['authorization'].strip().split(":")
        except Exception:
            logger.warning("authorization header is not correct")
            return Response({'error': 'authorization header is not correct'}, status=status.HTTP_400_BAD_REQUEST)
        
        path = serializer.validated_data['path']
        method = serializer.validated_data['method']
        encode_body = serializer.validated_data['encode_body']
        host = serializer.validated_data['host']

        current_timestamp = timezone.now().timestamp()
        request_timestamp = float(timestamp)
        allowed_time_difference = 60  

        if abs(current_timestamp - request_timestamp) > allowed_time_difference:
            logger.warning("Timestamp expired or invalid")
            return Response({'error': 'Timestamp expired or invalid'}, status=status.HTTP_401_UNAUTHORIZED)

        # Check for existing active session
        try:
            session = Session.objects.get(sessionId=session_id, expires__gt=timezone.now())
        except Session.DoesNotExist:
            logger.warning("Invalid or expired session")
            return Response({'error': 'Invalid or expired session'}, status=status.HTTP_401_UNAUTHORIZED)

        # Check if the session creation time is before the timestamp
        allowed_creation_delay = 1
        if session.created.timestamp() > request_timestamp + allowed_creation_delay:
            logger.warning("Session created after request timestamp")
            return Response({'error': 'Session created after request timestamp'}, status=status.HTTP_401_UNAUTHORIZED)
        
        if session.expires.timestamp() < request_timestamp:
            logger.warning("Session was expires when request was created")
            return Response({'error': 'Session was expires when request was created'}, status=status.HTTP_401_UNAUTHORIZED)
         
        if session.server.name != server_name:
            logger.warning("Session has been created not to this server")
            return Response({'error': 'Session has been created not to this server'}, status=status.HTTP_400_BAD_REQUEST)
         
        token = TemporaryToken.objects.filter(session=session,path=path).first()
        if not token:
            logger.warning("Token mismuch to session or path")
            return Response({'error': 'Token mismuch to session or path'}, status=status.HTTP_401_UNAUTHORIZED)
        
        message = f"{session.sessionId}{session.server.ip_address}{host}{method}{token.created_at}{session.user.username}{encode_body}"

        if not HmacToken.is_valid_hmac(hmac,token,message):
            logger.warning("invalid authorization header")
            return Response({'error': 'invalid authorization header'}, status=status.HTTP_401_UNAUTHORIZED)
        
        session.server.available = False
        session.server.user = session.user
        session.server.save()
        logger.info("Validation ok")
        return Response({'message': 'Validation ok'}, status=status.HTTP_200_OK)
       
class UpdateServerAvailabilityView(views.APIView): 
    """
    API view to update a server's availability status.
    """
    authentication_classes = [IPWhitelistAuthentication]  
    permission_classes = [AllowAny]
    throttle_classes = [UserRateThrottle]
       
    @csrf_exempt
    def patch(self, request, server_name: str) -> Response:
        """
        Updates the availability status of a server.
        
        Args:
            request (Request): The HTTP request containing availability data.
            server_name (str): The name of the server being updated.
        
        Returns:
            Response: JSON response indicating success or failure.
        """
        available = request.data.get('available')
        screens = request.data.get('screens')
        
        logger.info(f"Updating availability for server: {server_name}")

        if available is None:
            logger.warning('The "available" field is required')
            return Response({'error': 'The "available" field is required'}, status=status.HTTP_400_BAD_REQUEST)
        
        if not isinstance(available, bool):
            logger.warning('The "available" field must be a boolean')
            return Response({'error': 'The "available" field must be a boolean'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            server = Server.objects.get(name=server_name)
        except Server.DoesNotExist:
            logger.warning("Server not found")
            return Response({'error': 'Server not found'}, status=status.HTTP_404_NOT_FOUND)

        serializer = ServerAvailabilitySerializer(server, data=request.data, partial=True)
        
        if server.user:
            server.user = None

        if serializer.is_valid():
            serializer.save()
            logger.info(f"Server {server_name} availability updated successfully")
            return Response({'message': 'Server availability updated successfully'}, status=status.HTTP_200_OK)
        else:
            logger.warning(f"Failed to update server availability: {serializer.errors}")
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        
