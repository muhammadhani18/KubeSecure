from fastapi import APIRouter, Depends, HTTPException
from fastapi import Body
from fastapi.security import OAuth2PasswordRequestForm

from ..core.auth import create_access_token, authenticate_user, decode_token, get_password_hash
from ..schemas.auth import TokenResponse, SignupRequest
from ..core.config import ACCESS_TOKEN_EXPIRE
from ..core.mongo import get_db


router = APIRouter(prefix="/api", tags=["auth"])


@router.post("/login", response_model=TokenResponse)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    username = authenticate_user(form_data)
    access_token = create_access_token(data={"sub": username}, expires_delta=ACCESS_TOKEN_EXPIRE)
    return TokenResponse(access_token=access_token)


@router.get("/protected")
def protected_route(user: str = Depends(decode_token)):
    return {"message": "You have access to this protected route", "user": user}


@router.post("/signup", response_model=TokenResponse)
def signup(payload: SignupRequest):
    email = payload.email.strip().lower()
    password = payload.password
    if not email or not password:
        raise HTTPException(status_code=400, detail="email and password are required")

    db = get_db()
    existing = db.users.find_one({"email": email})
    if existing:
        raise HTTPException(status_code=409, detail="User already exists")

    password_hash = get_password_hash(password)
    db.users.insert_one({"email": email, "password_hash": password_hash})

    token = create_access_token(data={"sub": email}, expires_delta=ACCESS_TOKEN_EXPIRE)
    return TokenResponse(access_token=token)


