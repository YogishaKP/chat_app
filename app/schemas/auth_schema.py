from pydantic import BaseModel

class RequestOTPRequest(BaseModel):
    phone: str

class FirebaseLoginRequest(BaseModel):
    firebase_token: str