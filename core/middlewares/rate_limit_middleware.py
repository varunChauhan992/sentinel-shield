import re
import redis
from django.conf import settings
from django.http import JsonResponse
from core.models import SecurityLog, IPBlacklist

redis_client = redis.StrictRedis(
    host=getattr(settings, 'REDIS_HOST', '127.0.0.1'),
    port=getattr(settings, 'REDIS_PORT', 6379),
    db=getattr(settings, 'REDIS_DB', 0),
    decode_responses=True,
    socket_timeout=5,          # Prevents socket hanging
    socket_connect_timeout=5,  # Times out quickly if server is unreachable
    socket_keepalive=True,     # Keeps connection alive between requests
    retry_on_timeout=True      # Automatically retries dropped connection
)


class RateLimitMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
       
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR', '127.0.0.1')

       
        if request.path.startswith('/admin/') or request.path.startswith('/static/'):
            return self.get_response(request)

        redis_key = f"rate_limit:{ip}"
        rate_limit_max = getattr(settings, 'RATE_LIMIT_REQUESTS', 5)
        rate_limit_window = getattr(settings, 'RATE_LIMIT_WINDOW', 60)

        try:
           
            request_count = redis_client.incr(redis_key)
            if request_count == 1:
                redis_client.expire(redis_key, rate_limit_window)

            
            if request_count > rate_limit_max:
                SecurityLog.objects.create(
                    ip_address=ip,
                    endpoint=request.path,
                    event_type='RATE_LIMIT',
                    user_agent=request.META.get('HTTP_USER_AGENT', ''),
                    payload_sample=f"Limit exceeded: {request_count} requests in {rate_limit_window}s"
                )

                return JsonResponse(
                    {
                        "error": "Too Many Requests",
                        "message": f"Rate limit exceeded. Maximum {rate_limit_max} requests per {rate_limit_window} seconds allowed.",
                        "status": 429
                    },
                    status=429
                )

        except redis.RedisError as e:
            print(f"[SentinelShield Warning] Redis error: {e}")
        return self.get_response(request)


