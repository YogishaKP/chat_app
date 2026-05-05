import random
from app.db.redis_client import redis_client


def generate_otp():
    return str(random.randint(100000,999999))

def store_otp(phone: str, otp:str):
    key = f"otp:{phone}"
    redis_client.set(key, otp, ex=300)
    #otp:+919876543210 → 482193

def get_otp(phone: str):
    key = f"otp:{phone}"
    return redis_client.get(key)

def delete_otp(phone: str):
    key = f"otp:{phone}"
    redis_client.delete(key)