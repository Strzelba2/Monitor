from rest_framework import serializers
from .models import Server,Session

class ServerSerializer(serializers.ModelSerializer):
    class Meta:
        model = Server
        fields = ['name', 'ip_address', 'location']
        
class ServerAvailabilitySerializer(serializers.ModelSerializer):
    class Meta:
        model = Server
        fields = ['available']
        
class SessionIdSerializer(serializers.ModelSerializer):
    class Meta:
        model = Session
        fields = ['sessionId', 'expires']