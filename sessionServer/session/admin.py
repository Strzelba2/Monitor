from django.contrib import admin
from .models import BlockedIP , RequestLog
# Register your models here.

admin.site.register(BlockedIP)
admin.site.register(RequestLog)
