import json
from pathlib import Path
from datetime import datetime, timedelta, timezone
from typing import Annotated
from fastapi.params import Depends
from fastapi.security import OAuth2PasswordBearer
import jwt
from fastapi import HTTPException, status
from jwt.exceptions import InvalidTokenError
from . import token_factory 
from . import user
from . import user_token

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def load_users_db():
    db_file = Path(__file__).parent / "db.json"
    with open(db_file, "r") as f:
        return json.load(f)
    
def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return user.UserInDB(**user_dict)


def authenticate_user(fake_db, username: str, password: str):
    user = get_user(fake_db, username)
    if not user:
        token_factory.verify_password(password, token_factory.DUMMY_HASH)
        return False
    if not token_factory.verify_password(password, user.hashed_password):
        return False
    return user


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, token_factory.SECRET_KEY, algorithm=token_factory.ALGORITHM)
    return encoded_jwt



def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, token_factory.SECRET_KEY, algorithms=[token_factory.ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = user_token.TokenData(username=username)
    except InvalidTokenError:
        raise credentials_exception
    user = get_user(load_users_db(), username=token_data.username)
    if user is None:
        raise credentials_exception
    return user


def get_current_active_user(
    current_user: Annotated[user.User, Depends(get_current_user)],
):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user