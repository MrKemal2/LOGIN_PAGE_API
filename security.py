from fastapi.security import OAuth2PasswordBearer
from passlib.context import CryptContext
from datetime import datetime, timedelta, timezone
import jwt
from jwt.exceptions import InvalidTokenError
from fastapi import HTTPException, status, Depends
from typing import Annotated
from schemas import UserToken
import database as db

SECRET_KEY = "ASIRI_GIZLI_KEY"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="users/token")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(user_password, hashed_password):
    return pwd_context.verify(user_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_decode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_decode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_decode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"})
    try:
        print(f"Token received: {token[:20]}...")  # Debug için
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        print(f"Payload: {payload}")  # Debug için
        username: str = payload.get("sub")
        if username is None:
            print("Username is None")  # Debug için
            raise credentials_exception
        print(f"Username: {username}")  # Debug için
    except InvalidTokenError as e:
        print(f"Invalid token error: {e}")  # Debug için
        raise credentials_exception
    user = db.get_user(username)
    if user is None:
        print(f"User not found: {username}")  # Debug için
        raise credentials_exception
    print(f"User found: {user}")  # Debug için
    return user

async def get_current_admin_user(current_user: Annotated[dict, Depends(get_current_user)]):
    if not current_user.get("is_admin", False):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Bu işlemi yapmak için admin yetkisi gereklidir."
        )
    return current_user 