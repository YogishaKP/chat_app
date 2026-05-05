from app.db.redis_client import redis_client

MAX_REQUESTS = 3
WINDOW_SECONDS = 60

def is_rate_limited(phone: str) -> bool:
    key = f"rate:otp:{phone}"

    current = redis_client.get(key)

    if current is None:
        redis_client.set(key, 1, ex=WINDOW_SECONDS)
        return False
    
    if int(current) >= MAX_REQUESTS:
        return True
    
    redis_client.incr(key)
    return False