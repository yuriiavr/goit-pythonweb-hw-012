import os
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from passlib.context import CryptContext
from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
from sqlalchemy.orm import Session
import json
from redis.asyncio import Redis

from models import User, Role
from database import get_db

class Auth:
    pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")
    SECRET_KEY = os.environ.get("JWT_SECRET_KEY")
    ALGORITHM = os.environ.get("JWT_ALGORITHM")
    oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/auth/login")

    @staticmethod
    async def get_redis_client():
        r = await Redis(host=os.environ.get("REDIS_HOST"), port=int(os.environ.get("REDIS_PORT")), db=0)
        return r

    def verify_password(self, plain_password, hashed_password):
        return self.pwd_context.verify(plain_password, hashed_password)

    def get_password_hash(self, password):
        return self.pwd_context.hash(password)

    def create_access_token(self, data: dict, expires_delta: Optional[float] = None):
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.utcnow() + timedelta(seconds=expires_delta)
        else:
            expire = datetime.utcnow() + timedelta(minutes=15)
        to_encode.update({"iat": datetime.utcnow(), "exp": expire, "scope": "access_token"})
        encoded_jwt = jwt.encode(to_encode, self.SECRET_KEY, algorithm=self.ALGORITHM)
        return encoded_jwt

    def create_refresh_token(self, data: dict, expires_delta: Optional[float] = None):
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.utcnow() + timedelta(seconds=expires_delta)
        else:
            expire = datetime.utcnow() + timedelta(days=7)
        to_encode.update({"iat": datetime.utcnow(), "exp": expire, "scope": "refresh_token"})
        encoded_jwt = jwt.encode(to_encode, self.SECRET_KEY, algorithm=self.ALGORITHM)
        return encoded_jwt

    def create_email_token(self, data: dict, expires_delta: Optional[float] = None):
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.utcnow() + timedelta(seconds=expires_delta)
        else:
            expire = datetime.utcnow() + timedelta(days=1)
        to_encode.update({"iat": datetime.utcnow(), "exp": expire, "scope": "email_token"})
        encoded_jwt = jwt.encode(to_encode, self.SECRET_KEY, algorithm=self.ALGORITHM)
        return encoded_jwt

    def decode_refresh_token(self, refresh_token: str):
        try:
            payload = jwt.decode(refresh_token, self.SECRET_KEY, algorithms=[self.ALGORITHM])
            if payload['scope'] == 'refresh_token':
                email = payload['sub']
                return email
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid scope for token')
        except JWTError:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Could not validate credentials')

    def decode_email_token(self, token: str):
        try:
            payload = jwt.decode(token, self.SECRET_KEY, algorithms=[self.ALGORITHM])
            if payload['scope'] == 'email_token':
                email = payload["sub"]
                return email
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid scope for token')
        except JWTError as e:
            print(e)
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid token for email verification")

    async def get_current_user(self, token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
        credentials_exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

        try:
            payload = jwt.decode(token, self.SECRET_KEY, algorithms=[self.ALGORITHM])
            if payload['scope'] != 'access_token':
                raise credentials_exception
            email = payload.get("sub")
            if email is None:
                raise credentials_exception
        except JWTError as e:
            raise credentials_exception

        redis_client = await Auth.get_redis_client()
        cached_user_json = await redis_client.get(f"user:{email}")

        if cached_user_json:
            user_data = json.loads(cached_user_json)
            user_data['role'] = Role(user_data['role'])
            if 'created_at' in user_data and isinstance(user_data['created_at'], str):
                user_data['created_at'] = datetime.fromisoformat(user_data['created_at'])
            return User(**user_data)

        user = db.query(User).filter(User.email == email).first()
        if user is None:
            raise credentials_exception

        user_data = {c.name: getattr(user, c.name) for c in user.__table__.columns}
        
        if 'created_at' in user_data and user_data['created_at'] is not None:
             user_data['created_at'] = user_data['created_at'].isoformat()
             
        user_data['role'] = user_data['role'].value
        await redis_client.set(f"user:{email}", json.dumps(user_data), ex=3600)

        return user

    def get_user_by_email(self, email: str, db: Session = Depends(get_db)):
        return db.query(User).filter(User.email == email).first()

auth_service = Auth()

def role_required(required_role: Role):
    def wrapper(current_user: User = Depends(auth_service.get_current_user)):
        if current_user.role.value != required_role.value:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"User must have {required_role.value} role to perform this action")
        return current_user
    return wrapper