import requests
from django.conf import settings

def verify_turnstile(token, remote_ip=None):
    if getattr(settings, "TEST_MODE", True):
        # Test mode da token har doim o‘tadi
        return True
    url = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
    data = {
        "secret": settings.TURNSTILE_SECRET_KEY,
        "response": token,
    }
    if remote_ip:
        data["remoteip"] = remote_ip

    resp = requests.post(url, data=data)
    result = resp.json()
    return result.get("success", False)