from django.contrib import admin
from .models import BlockedIP , RequestLog, Server, Session, TemporaryToken

# Register your models here.

admin.site.register(BlockedIP)
admin.site.register(RequestLog)
admin.site.register(Server)
admin.site.register(Session)
admin.site.register(TemporaryToken)
