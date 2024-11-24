from django.utils import timezone
from oauth2_provider.models import AccessToken
from oauth2_provider.contrib.rest_framework import TokenHasReadWriteScope
from rest_framework import views, status
from rest_framework.response import Response
from rest_framework.throttling import UserRateThrottle
from rest_framework.permissions import IsAuthenticated
from .models import Server,Session
from .serializers import ServerSerializer,ServerAvailabilitySerializer,SessionIdSerializer
from .authentication import IPWhitelistAuthentication
from django.conf import settings
import uuid
import base64

 
class AvailableServersView(views.APIView):
    permission_classes = [IsAuthenticated, TokenHasReadWriteScope]
    throttle_classes = [UserRateThrottle]

    def get(self, request):
        servers = Server.objects.filter(available=True)
        serializer = ServerSerializer(servers, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
class GenerateSessionView(views.APIView):
    permission_classes = [IsAuthenticated, TokenHasReadWriteScope]
    throttle_classes = [UserRateThrottle]

    def post(self, request):
        user = request.user
        server_id = request.data.get('server_id')

        if not server_id:
            return Response({'error': 'Server ID is required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            server = Server.objects.get(id=server_id)
        except Server.DoesNotExist:
            return Response({'error': 'Server not found'}, status=status.HTTP_404_NOT_FOUND)

        # Check for existing active session
        existing_session = Session.objects.filter(user=user, server=server, expires__gt=timezone.now()).first()

        if existing_session:
            serializer = SessionIdSerializer(existing_session)
            return Response(serializer.data, status=status.HTTP_200_OK)

        # Generate a new session
        session_id = uuid.uuid4().hex
        expires = timezone.now() + timezone.timedelta(hours=1) 

        new_session = Session.objects.create(user=user, sessionId=session_id, server=server, expires=expires)

        serializer = SessionIdSerializer(new_session)
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    
class VerifySessionView(views.APIView):
    
    authentication_classes = [IPWhitelistAuthentication]
    throttle_classes = [UserRateThrottle]

    def post(self, request):
        session_id = request.data.get('sessionId')
        server_name = request.data.get('server_name')
        timestamp = request.data.get('timestamp')
        
        if not session_id or not server_name or not timestamp:
            return Response({'error': 'Session ID, server name, and timestamp are required'}, status=status.HTTP_400_BAD_REQUEST)

        current_timestamp = timezone.now().timestamp()
        request_timestamp = float(timestamp)
        allowed_time_difference = 60  

        if abs(current_timestamp - request_timestamp) > allowed_time_difference:
            return Response({'error': 'Timestamp expired or invalid'}, status=status.HTTP_401_UNAUTHORIZED)

        # Check for existing active session
        try:
            session = Session.objects.get(sessionId=session_id, expires__gt=timezone.now())
        except Session.DoesNotExist:
            return Response({'error': 'Invalid or expired session'}, status=status.HTTP_401_UNAUTHORIZED)

        # Check if the session creation time is before the timestamp
        if session.created.timestamp() > request_timestamp:
            return Response({'error': 'Session created after request timestamp'}, status=status.HTTP_401_UNAUTHORIZED)

        # Check if the server name matches
        if session.server.name != server_name:
            return Response({'error': 'Server name mismatch'}, status=status.HTTP_401_UNAUTHORIZED)
        
        try:
            token = AccessToken.objects.get(user=session.user, expires__gt=timezone.now())
        except AccessToken.DoesNotExist:
            return Response({'error': 'User token expired or invalid'}, status=status.HTTP_401_UNAUTHORIZED)
        
        encoded_token = base64.b64encode(token.token.encode()).decode()
        
        return Response({
            'token': encoded_token 
        }, status=status.HTTP_200_OK)
        
class UpdateServerAvailabilityView(views.APIView): 
    authentication_classes = [IPWhitelistAuthentication]  
       
    def patch(self, request, server_name):
        available = request.data.get('available')

        if available is None:
            return Response({'error': 'The "available" field is required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            server = Server.objects.get(name=server_name)
        except Server.DoesNotExist:
            return Response({'error': 'Server not found'}, status=status.HTTP_404_NOT_FOUND)

        serializer = ServerAvailabilitySerializer(server, data=request.data, partial=True)

        if serializer.is_valid():
            serializer.save()
            return Response({'message': 'Server availability updated successfully'}, status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)