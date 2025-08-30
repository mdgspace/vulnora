import os
import jwt
from flask import request, jsonify

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
        return decoded.get("user_id")   
    except jwt.ExpiredSignatureError:
        return None  # token expired
    except jwt.InvalidTokenError:
        return None  # invalid token
