from django.db import models

class SecurityLog(models.Model):
    """stores security threats , rate limits violatons , and payload attacks"""
    EVENT_TYPES = [
        ('RATE_LIMIT' , 'RATE_LIMIT_EXCEEDED'),
        ('BRUTE_FORCE', 'BRUTE_FORCE_ATTEMPT'),
        ('SQL_INJECTION', 'SQL_INJECTION_ATTEMPT'),
        ('XSS_ATTACK', 'XSS_ATTACK_ATTEMPT'),
    ]

    ip_address = models.GenericIPAddressField()
    endpoint = models.CharField(max_length=255)
    event_type = models.CharField(max_length=20, choices=EVENT_TYPES)
    user_agent = models.TextField(blank= True , null =True)
    payload_sample = models.TextField(blank= True , null = True)
    timestamp  = models.DateTimeField(auto_now_add= True)

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        return f"{self.event_type} from {self.ip_address} on {self.endpoint}"

class IPBlacklist(models.Model):
    """stores blacklisted IP addresses"""
    ip_address = models.GenericIPAddressField(unique= True)
    reason = models.CharField(max_length= 255)
    blocked_at = models.DateTimeField(auto_now_add= True)
    is_active = models.BooleanField(default= True)
    
    def __str__(self):
        return f"{self.ip_address}-blocked for {self.reason} : {'active' if self.is_active else 'inactive'}"