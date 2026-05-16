from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from datetime import datetime, timedelta, UTC
import random
import jwt
import os
from dotenv import load_dotenv
import uuid
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi import Depends

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

security = HTTPBearer()

# In memory storage
otp_store = {}
users = {}

# Request Models
class RegisterRequest(BaseModel):
    phone: str

class LoginRequest(BaseModel):
    phone: str

class VerifyRequest(BaseModel):
    phone: str
    otp: str

class RefreshRequest(BaseModel):
    refresh_token: str

class UpdateProfileRequest(BaseModel):
    name: str
    email: str
    
# Helpers
def generate_otp():
    return str(random.randint(100000,999999))

def create_access_token(phone: str):
    expire = utcnow() + timedelta(minutes=int(ACCESS_TOKEN_EXPIRE_MINUTES))
    

    payload = {
        "sub": users[phone]["user_id"],
        "type": "access",
        "exp": expire
    }

    return jwt.encode(payload, JWT_SECRET, algorithm=ALGORITHM)

def create_refresh_token(phone: str):
    expire = utcnow() + timedelta(days=int(REFRESH_TOKEN_EXPIRE_DAYS))
    payload = {
        "sub": users[phone]["user_id"],
        "type": "refresh",
        "exp": expire
    }

    return jwt.encode(payload, JWT_SECRET, algorithm=ALGORITHM)

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials

    try:
        payload = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=[ALGORITHM]
        )

        # validate token type
        if payload["type"] != "access":
            raise HTTPException(
                status_code=401,
                detail="Invalid access token"
            )
        
        token_user_id = payload["sub"]

        # find user
        for user in users.values():
            if user["user_id"] == token_user_id:
                return user
        
        raise HTTPException(
            status_code=404,
            detail="User not found"
        )
    
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=401,
            detail="Access token expired"
        )
    
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=401,
            detail="Invalid token"
        )

# Routes
@app.post("/api/v1/auth/register")
def register(data: RegisterRequest):


    # check for existing user
    if data.phone in users:
        raise HTTPException(
            status_code=400,
            detail="User already exists"
        )
    
    # creaate user
    users[data.phone] = {
        "user_id": str(uuid.uuid4()),
        "phone": data.phone,
        "name": None,
        "email": None,
        "verified": False,
        "created_at": utcnow()
    }


    # generate otp
    otp = generate_otp()

    otp_store[data.phone]={
        "otp": otp,
        "expires_at": utcnow() + timedelta(minutes=5)
    }

    # simulate sms
    print(f"Registered OTP for {data.phone}: {otp}")

    return {
        "message":"User Registered. OTP sent",
        "otp":otp
    }

@app.post("/api/v1/auth/login")
def login(data: LoginRequest):

    # check user exists
    if data.phone not in users:
        raise HTTPException(
            status_code=404,
            detail="User not found"
        )
    
    # generate otp
    otp = generate_otp()

    otp_store[data.phone]={
        "otp":otp,
        "expires_at": utcnow() + timedelta(minutes=5)
    }

    # simulate sms
    print(f"LOGIN OTP for {data.phone}: {otp}")

    return {
        "message": "OTP Sent for Login",
        "otp": otp
    }

@app.post("/api/v1/auth/verify")
def vrify(data: VerifyRequest):

    record = otp_store.get(data.phone)

    if not record:
        raise HTTPException(
            status_code=404,
            detail="OTP not found"
        )
    
    # check expiry
    if utcnow() > record["expires_at"]:
        raise HTTPException(
            status_code=400,
            detail="OTP expired"
        )
    
    # check otp
    if record["otp"] != data.otp:
        raise HTTPException(
            status_code=400,
            detail="Invalid OTP"
        )
    
    # mark as verified
    users[data.phone]["verified"] = True

    # create tokens
    access_token = create_access_token(data.phone)
    refresh_token = create_refresh_token(data.phone)

    # remove otp
    del otp_store[data.phone]

    return {
        "message": "OTP Verified",
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "user_id": users[data.phone]["user_id"]
    }

@app.post("/api/v1/auth/refresh")
def refresh(data: RefreshRequest):
    
    try:
        payload = jwt.decode(
            data.refresh_token,
            JWT_SECRET,
            algorithms=[ALGORITHM]
        )
        print("pay",payload)

        # validate token type
        if payload["type"] != "refresh":
            raise HTTPException(
                status_code=401,
                detail="Invalid token type"
            )
        
        user_id = payload["sub"]

        for user in users.values():
            if user["user_id"] == user_id:
                phone = user["phone"]

        # create new access token
        access_token = create_access_token(phone)

        return {
            "access_token": access_token,
            "token_type": "bearer"
        }
    
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=401,
            detail="Refresh token expired"
        )
    
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=401,
            detail="Invalid refresh token"
        )
    
@app.get("/api/v1/users/{user_id}")
def get_user_profile(user_id:str, current_user = Depends(get_current_user)):

    # compare token user_id vs url user_id
    if current_user["user_id"] != user_id:
        raise HTTPException(
            status_code=403,
            detail="Access denied"
        )

    return {
        "user_id": current_user["user_id"],
        "phone": current_user["phone"],
        "name": current_user["name"],
        "email": current_user["email"],
        "verified": current_user["verified"]
    }

@app.put("/api/v1/users/{user_id}")
def update_user_profile(user_id: str, data:UpdateProfileRequest, current_user = Depends(get_current_user)):

    # compare token user_id vs url user_id
    if current_user["user_id"] != user_id:
        raise HTTPException(
            status_code="403",
            detail="Access denied"
        )

    # update profile
    current_user["name"] = data.name
    current_user["email"] = data.email
    current_user["last_updated"] = utcnow()

    return {
        "message": "Profile updated successfully",
        "user": {
            "user_id": current_user["user_id"],
            "phone": current_user["phone"],
            "name": current_user["name"],
            "email": current_user["email"],
            "last_updated": current_user["last_updated"]
        }
    }