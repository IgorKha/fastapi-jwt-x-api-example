from datetime import datetime, timedelta, timezone
from typing import Annotated, Any, Optional

import jwt
from fastapi import Depends, FastAPI, HTTPException, Security, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm, APIKeyHeader
from jwt.exceptions import InvalidTokenError
from passlib.context import CryptContext
from pydantic import BaseModel

# to get a string like this run:
# openssl rand -hex 32
SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
SECRET_API_KEY: str = "8c85224d1d49f6dc1471376377c05138d419028b15786343fc3305cd21361c91"

fake_users_db = {
    "admin": {
        "username": "admin",
        "full_name": "John Doe",
        "email": "johndoe@example.com",
        "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",
        "disabled": False,
    }
}

api_key_db = {
    "Server": {
        "key": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJrZXlfbmFtZSI6IlNlcnZlciIsIndyaXRlX2FjY2VzcyI6ZmFsc2UsImlhdCI6MTcxOTc3MzI3N30.Iz4N-r2-A8Gih8o-yJnVH1qjSMNj3TfAlMroahKh_W8",
        "disabled": False,
    }
}


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str | None = None


class User(BaseModel):
    username: str
    email: str | None = None
    full_name: str | None = None
    disabled: bool | None = None


class UserInDB(User):
    hashed_password: str


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
api_key_header_scheme = APIKeyHeader(name="X-API-Key", scheme_name="API Key")

app = FastAPI()


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)


def authenticate_user(fake_db, username: str, password: str):
    user = get_user(fake_db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except InvalidTokenError:
        raise credentials_exception

    user: UserInDB | None = get_user(
        fake_users_db, username=token_data.username)  # type: ignore
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user(
    current_user: Annotated[User, Depends(get_current_user)],
):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


def decode_api_key(key: str) -> dict:
    try:
        decoded_jwt = jwt.decode(key, SECRET_API_KEY, algorithms=[ALGORITHM])
        return decoded_jwt
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid API key"
        )


def get_key_name_from_api_key(api_key: str):
    decoded_jwt = decode_api_key(api_key)
    key_name = decoded_jwt.get("key_name")
    # Проверяем, есть ли ключ с таким key_name и активен ли он
    if key_name is not None:
        return None
    if key_name is not None and key_name in api_key_db:
        if api_key_db[key_name]["disabled"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="API key is deactivated"
            )
        return key_name
    else:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Key name is not valid"
        )

# Use this dependency to get the key name from the API key (Depends(auth_api_key))


def auth_api_key(api_key_header: str = Security(api_key_header_scheme)):
    try:
        key_name = get_key_name_from_api_key(api_key_header)
        print(f"Key name: {key_name}")
        return key_name
    except HTTPException as e:
        # Перехватываем исключение и пробрасываем дальше
        raise e


def create_api_key(data: dict) -> str:
    to_encode = data.copy()
    encoded_jwt: str = jwt.encode(
        to_encode, SECRET_API_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def combined_auth(
    token: Optional[str] = Depends(get_current_user),
    api_key: Optional[str] = Security(api_key_header_scheme)
):
    if token:
        return await get_current_user(token)
    elif api_key:
        return await auth_api_key(api_key)  # type: ignore
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )


async def jwt_or_key_auth(jwt_result: Annotated[Any, Depends(get_current_active_user)] = None, key_result: Annotated[Any, Depends(auth_api_key)] = None):
    if jwt_result is not None:
        return jwt_result
    elif key_result is not None:
        return key_result
    if not (key_result or jwt_result):
        raise HTTPException(status_code=401, detail="Not authenticated")


@app.post("/token")
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
) -> Token:
    user = authenticate_user(
        fake_users_db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return Token(access_token=access_token, token_type="bearer")


@app.get("/users/me/", response_model=User)
async def read_users_me(
    current_user: Annotated[User, Depends(get_current_active_user)],
):
    return current_user


@app.get("/users/me/items/")
async def read_own_items(
    current_user: Annotated[User, Depends(jwt_or_key_auth)],
):
    return [{"item_id": "Foo", "owner": "bar"}]
