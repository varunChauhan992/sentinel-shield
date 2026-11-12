import re
import urllib.parse
from django.http import JsonResponse
from core.models import IPBlacklist, SecurityLog

# Regular expressions for threat detection
SQLI_REGEX = re.compile(
    r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|CREATE)\b|'|--|\bOR\b\s+['\d]=['\d])",
    re.IGNORECASE
)

XSS_REGEX = re.compile(
    r"(<script.*?>|%3cscript.*?|javascript:|onload=|onerror=|<img.*?>|<iframe.*?>)",
    re.IGNORECASE
)


class ThreatDetectionMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        ip = self.get_client_ip(request)

        if IPBlacklist.objects.filter(ip_address=ip, is_active=True).exists():
            return JsonResponse(
                {
                    "error": "Access Denied",
                    "message": "Your IP address has been permanently blocked."
                },
                status=403
            )

        # 2. Extract and decode query string & GET parameter values
        raw_query_string = request.META.get('QUERY_STRING', '')
        decoded_query_string = urllib.parse.unquote(raw_query_string)
        
        get_values_raw = " ".join([f"{k}={v}" for k, v in request.GET.items()])
        get_values_decoded = urllib.parse.unquote(get_values_raw)

        # 3. Extract request body content if present
        body_content = ""
        try:
            if request.body:
                body_content = request.body.decode('utf-8', errors='ignore')
        except Exception:
            body_content = ""

        # Aggregate all inputs into a single text target for pattern matching
        target_payload = f"{raw_query_string} {decoded_query_string} {get_values_raw} {get_values_decoded} {body_content}"

        # 4. Check for SQL Injection
        if SQLI_REGEX.search(target_payload):
            SecurityLog.objects.create(
                ip_address=ip,
                event_type="SQL_INJECTION",
                endpoint=request.path,
                payload_sample=target_payload[:250]
            )
            return JsonResponse(
                {
                    "error": "Bad Request",
                    "message": "Malicious payload detected (SQL Injection)."
                },
                status=400
            )

        # 5. Check for XSS
        if XSS_REGEX.search(target_payload):
            SecurityLog.objects.create(
                ip_address=ip,
                event_type="XSS_ATTACK",
                endpoint=request.path,
                payload_sample=target_payload[:250]
            )
            return JsonResponse(
                {
                    "error": "Bad Request",
                    "message": "Malicious payload detected (XSS)."
                },
                status=400
            )

        return self.get_response(request)

    def get_client_ip(self, request):
        """Extract client IP address, accounting for reverse proxies."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR', '127.0.0.1')