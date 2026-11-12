from django.contrib import admin
from .models import SecurityLog, IPBlacklist

@admin.register(SecurityLog)
class SecurityLogAdmin(admin.ModelAdmin):
    list_display = ('ip_address', 'endpoint','event_type','timestamp')
    list_filter = ('event_type', 'timestamp')
    search_fields = ('ip_address', 'endpoint', 'payload_sample')

@admin.register(IPBlacklist)
class IPBlacklistAdmin(admin.ModelAdmin):
    list_display = ('ip_address', 'reason','blocked_at', 'is_active')
    list_filter =('is_active', 'blocked_at')
    search_fields = ('ip_address', 'reason')

