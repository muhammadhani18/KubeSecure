from datetime import datetime, timedelta
from typing import Dict, Optional

from fastapi import HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import jwt, JWTError
from passlib.context import CryptContext
from passlib.exc import UnknownHashError

from .config import SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE
from .mongo import get_db


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/login")


def create_access_token(data: Dict, expires_delta: timedelta = ACCESS_TOKEN_EXPIRE) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")


def verify_password(plain_password: str, hashed_password: str) -> bool:
	try:
		return pwd_context.verify(plain_password, hashed_password)
	except (UnknownHashError, ValueError, TypeError):
		# Unknown or malformed hash → treat as invalid password
		return False


def get_password_hash(password: str) -> str:
	return pwd_context.hash(password)


def authenticate_user(form_data: OAuth2PasswordRequestForm = Depends()):
	username_input = (form_data.username or "").strip().lower()
	password_input = form_data.password or ""
	db = get_db()
	user: Optional[Dict] = db.users.find_one({"email": username_input})
	if not user or not verify_password(password_input, user.get("password_hash", "")):
		raise HTTPException(status_code=401, detail="Invalid username or password")
	return username_input


def decode_token(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return username
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


