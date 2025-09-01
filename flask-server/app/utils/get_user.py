import os
import jwt
from flask import request, jsonify
from dotenv import load_dotenv

load_dotenv() 

JWT_SECRET = os.getenv("JWT_SECRET")
JWT_ALGORITHM = "HS256"

def get_user():
    """Extract user_id from JWT in Authorization header"""
    auth_header = request.headers.get("Authorization", None)
    if not auth_header or not auth_header.startswith("Bearer "):
        return None  
    
    token = auth_header.split(" ")[1]

    try:
        # Decode token using the same secret + HS256 algorithm
        decoded = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        print("[DECODED JWT CLAIMS]", decoded)
        auth_header = request.headers.get("Authorization", None)
        print("[AUTH HEADER RAW]", auth_header)

        return decoded.get("user_id") or decoded.get("UserID")
  
    except jwt.ExpiredSignatureError:
        return None  # token expired
    except jwt.InvalidTokenError:
        return None  # invalid token
