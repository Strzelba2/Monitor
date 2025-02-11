from rest_framework import serializers
from .models import Server,Session

class UpdateSessionSerializer(serializers.Serializer):
    session_id = serializers.CharField(required=True)
     
class GenerateSessionSerializer(serializers.Serializer):
    server_name = serializers.CharField(required=True)
    
class GeneratetokenSerializer(serializers.Serializer):
    server_name = serializers.CharField(required=True)
    encode_body = serializers.CharField(required=True, allow_blank=True)
    method = serializers.CharField(required=True)
    path = serializers.CharField(required=True)
    
class VerifySessionSerializer(serializers.Serializer):
    authorization = serializers.CharField(required=True)
    path = serializers.CharField(required=True)
    encode_body = serializers.CharField(required=True, allow_blank=True)
    method = serializers.CharField(required=True)
    host = serializers.CharField(required=True)
        
class ServerAvailabilitySerializer(serializers.ModelSerializer):
    class Meta:
        model = Server
        fields = ['available','screens']
        
class SessionIdSerializer(serializers.ModelSerializer):
    class Meta:
        model = Session
        fields = ['sessionId', 'expires']
        
class ServerSerializer(serializers.ModelSerializer):
    class Meta:
        model = Server
        fields = ['name', 'ip_address', 'location']