from fastapi import APIRouter
from app.schemas.auth_schema import RequestOTPRequest
from app.services.otp_service import generate_otp, store_otp
from app.services.rate_limiter import is_rate_limited
from app.schemas.auth_schema import FirebaseLoginRequest
from firebase_admin import auth as firebase_auth

router = APIRouter()

@router.post("/request-otp")
def request_otp(request: RequestOTPRequest):

    phone = request.phone

    if is_rate_limited(phone):
        return {
            "status": "error",
            "message": "Too many requests. Try again later."
        }

    otp = generate_otp()

    store_otp(phone, otp)

    print(f"OTP for {phone}: {otp}")

    return {
        "status": "success",
        "message": "OTP sent successfully"
    }

@router.post("/firebase-login")
def firebase_login(request: FirebaseLoginRequest):
    try:
        # Step 1: Verify Firebase token
        decoded_token = firebase_auth.verify_id_token(request.firebase_token)

        phone = decoded_token.get("phone_number")
        if not phone:
            return {
                "status": "error",
                "message": "Phone number not found"
            }

        # Step 2: Here we will later check Cassandra
        # (for now just return success)

        return {
            "status": "success",
            "data": {
                "phone": phone,
                "message": "User authenticated via Firebase"
            }
        }
    except Exception as e:
        return {
            "status": "error",
            "message": "Invalid Firebase token"
        }