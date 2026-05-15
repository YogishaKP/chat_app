from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from datetime import datetime, timedelta, UTC
import random
import jwt
import os
from dotenv import load_dotenv

load_dotenv()

def utcnow():
    """Returns the current UTC date and time (Timezone-Aware)."""
    return datetime.now(UTC)

app = FastAPI()

@app.get("/")
def home():
    return {"status":"success","message":"Welcome to home page"}

# Config
JWT_SECRET = os.getenv("JWT_SECRET")
ACCESS_TOKEN_EXPIRE_MINUTES = os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES",15)
REFRESH_TOKEN_EXPIRE_DAYS = os.getenv("REFRESH_TOKEN_EXPIRE_DAYS",7)

ALGORITHM = "HS256"

# In memory storage
otp_store = {}

# Request Models
class PhoneRequest(BaseModel):
    phone: str

class VerifyOTPRequest(BaseModel):
    phone: str
    otp: str

# Helpers
def generate_otp():
    return str(random.randint(100000,999999))

def create_access_token(phone: str):
    expire = utcnow() + timedelta(minutes=int(ACCESS_TOKEN_EXPIRE_MINUTES))
    payload = {
        "sub": phone,
        "type": "access",
        "exp": expire
    }

    return jwt.encode(payload, JWT_SECRET, algorithm=ALGORITHM)

def create_refresh_token(phone: str):
    expire = utcnow() + timedelta(days=int(REFRESH_TOKEN_EXPIRE_DAYS))
    payload = {
        "sub": phone,
        "type": "refresh",
        "exp": expire
    }

    return jwt.encode(payload, JWT_SECRET, algorithm=ALGORITHM)

# Routes
@app.post("/generate-otp")
def generate_otp_api(data: PhoneRequest):
    otp = generate_otp()

    otp_store[data.phone]={
        "otp": otp,
        "expires_at": utcnow() + timedelta(minutes=5)
    }

    print(f"OTP for {data.phone}: {otp}")

    return {
        "message": "OTP sent successfully",
        "otp_is": otp
    }

@app.post("/verify-otp")
def verify_otp_api(data: VerifyOTPRequest):
    print(otp_store)

    record = otp_store.get(data.phone)

    if not record:
        raise HTTPException(
            status_code=404,
            detail="OTP not found"
        )
    
    if utcnow() > record["expires_at"]:
        raise HTTPException(
            status_code=400,
            data="OTP expired"
        )
    
    if record["otp"] != data.otp:
        raise HTTPException(
            status_code=400,
            data="Invalid OTP"
        )
    
    # OTP verified
    access_token = create_access_token(data.phone)
    refresh_token = create_refresh_token(data.phone)

    # Remove otp after successful verification
    del otp_store[data.phone]

    return {
        "message": "User verified",
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }