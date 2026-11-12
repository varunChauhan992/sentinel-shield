
from functools import wraps
from django.contrib.auth.views import redirect_to_login
from django.core.exceptions import PermissionDenied
from django.shortcuts import render, redirect
from django.db.models import Count
from django.contrib import messages
from rest_framework.decorators import api_view
from rest_framework.response import Response
from django.views.decorators.http import require_POST
from .models import SecurityLog, IPBlacklist


@api_view(['GET']) # Decorator wraps request, parses URL params, and converts dict output to JSON
def public_data_view(request):
    """public endpoint to simulate normal traffic"""
    return Response({
        "status": "success",
        "message": "welcome to sentinelShield public API data"
    })

@api_view(['POST']) # Formats request/response JSON, handles content type headers and enforces HTTP method
def mock_login_view(request):
    """Mock auth endpoint to test brute-force protection later"""
    username = request.data.get("username")
    password = request.data.get("password")
    
    if username == "admin" and password == "secret123":
        return Response({
            "status": "success",
            "token": "mock-jwt-token-xyz"
        })
    return Response({"status": "error", "message": "Invalid credentials"}, status=400)


def superuser_required(view_func):
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect_to_login(request.get_full_path(), login_url='/admin/login/')
        if not request.user.is_superuser:
            raise PermissionDenied
        return view_func(request, *args, **kwargs)
    return wrapper



@superuser_required
def soc_dashboard(request):
    """Renders the main SOC Security Analytics Dashboard."""
    total_logs = SecurityLog.objects.count()
    
    # Aggregated threat breakdown by event_type
    threat_counts = list(
        SecurityLog.objects.values('event_type')
        .annotate(count=Count('event_type'))
        .order_by('-count')
    )
    
    recent_logs = SecurityLog.objects.all().order_by('-timestamp')[:15]
    blacklisted_ips = IPBlacklist.objects.all().order_by('-blocked_at')

    context = {
        'total_logs': total_logs,
        'threat_counts': threat_counts,
        'recent_logs': recent_logs,
        'blacklisted_ips': blacklisted_ips,
    }
    return render(request, 'dashboard.html', context)


@superuser_required
@require_POST
def toggle_block_ip(request, ip_address):
    """Toggles active status of an IP address in IPBlacklist."""
    blacklist_entry, created = IPBlacklist.objects.get_or_create(
        ip_address=ip_address,
        defaults={'reason': 'Manually managed via SOC Dashboard', 'is_active': True}
    )
    
    if not created:
        blacklist_entry.is_active = not blacklist_entry.is_active
        blacklist_entry.save()
        status_msg = "blocked" if blacklist_entry.is_active else "unblocked"
    else:
        status_msg = "blocked"

    messages.success(request, f"IP address {ip_address} successfully {status_msg}.")
    return redirect('soc_dashboard')