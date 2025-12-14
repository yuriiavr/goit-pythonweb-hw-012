import os
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from passlib.context import CryptContext
from datetime import datetime, timedelta
from typing import Optional, List
from jose import JWTError, jwt
from sqlalchemy.orm import Session
import json
from redis.asyncio import Redis

from models import User, Role
from database import get_db
import crud

class Auth:
    pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")
    SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "your_secret_key")
    ALGORITHM = os.environ.get("JWT_ALGORITHM", "HS256")
    oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/auth/login")

    @staticmethod
    async def get_redis_client() -> Redis:
        redis_host = os.environ.get("REDIS_HOST", "localhost")
        redis_port = int(os.environ.get("REDIS_PORT", 6379))
        r = await Redis(host=redis_host, port=redis_port, db=0)
        return r

    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        return self.pwd_context.verify(plain_password, hashed_password)

    def get_password_hash(self, password: str) -> str:
        return self.pwd_context.hash(password)

    def create_token(self, data: dict, token_type: str, expires_delta: Optional[float] = None) -> str:
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.utcnow() + timedelta(seconds=expires_delta)
        else:
            if token_type == "access_token":
                expire = datetime.utcnow() + timedelta(minutes=15)
            elif token_type == "refresh_token":
                expire = datetime.utcnow() + timedelta(days=7)
            elif token_type in ["email_token", "reset_token"]:
                expire = datetime.utcnow() + timedelta(minutes=15)
            else:
                expire = datetime.utcnow() + timedelta(minutes=15)
                
        to_encode.update({"iat": datetime.utcnow(), "exp": expire, "scope": token_type})
        encoded_jwt = jwt.encode(to_encode, self.SECRET_KEY, algorithm=self.ALGORITHM)
        return encoded_jwt

    def create_access_token(self, data: dict, expires_delta: Optional[float] = None) -> str:
        return self.create_token(data, "access_token", expires_delta)

    def create_refresh_token(self, data: dict, expires_delta: Optional[float] = None) -> str:
        return self.create_token(data, "refresh_token", expires_delta)
        
    def create_email_token(self, data: dict, expires_delta: Optional[float] = None) -> str:
        return self.create_token(data, "email_token", expires_delta)

    def create_reset_token(self, data: dict, expires_delta: Optional[float] = None) -> str:
        return self.create_token(data, "reset_token", expires_delta)

    def decode_token(self, token: str, scopes: List[str]) -> str:
        credentials_exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
        try:
            payload = jwt.decode(token, self.SECRET_KEY, algorithms=[self.ALGORITHM])
            email = payload.get("sub")
            scope = payload.get("scope")
            
            if email is None or scope not in scopes:
                raise credentials_exception
            return email
        except JWTError:
            raise credentials_exception

    def decode_refresh_token(self, refresh_token: str) -> str:
        return self.decode_token(refresh_token, ["refresh_token"])

    def decode_email_token(self, token: str) -> str:
        return self.decode_token(token, ["email_token"])

    def decode_reset_token(self, token: str) -> str:
        return self.decode_token(token, ["reset_token"])

    async def get_current_user(self, token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
        credentials_exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
        
        email = self.decode_token(token, ["access_token"])
        
        redis_client = await self.get_redis_client()
        cached_user_json = await redis_client.get(f"user:{email}")

        if cached_user_json:
            user_data = json.loads(cached_user_json)
            user = crud.get_user_by_email(db, email) 
            if user is None:
                raise credentials_exception
            if not user.confirmed:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED, 
                    detail="Email not confirmed", 
                    headers={"WWW-Authenticate": "Bearer"}
                )
            return user
            
        user = crud.get_user_by_email(db, email)
        if user is None:
            raise credentials_exception
        
        if not user.confirmed:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, 
                detail="Email not confirmed", 
                headers={"WWW-Authenticate": "Bearer"}
            )

        user_data = {c.name: getattr(user, c.name) for c in user.__table__.columns}
        
        if 'created_at' in user_data and user_data['created_at'] is not None:
             user_data['created_at'] = user_data['created_at'].isoformat()
             
        user_data['role'] = user_data['role'].value
        await redis_client.set(f"user:{email}", json.dumps(user_data), ex=3600)

        return user

auth_service = Auth()

def role_required(required_role: Role):
    def wrapper(current_user: User = Depends(auth_service.get_current_user)) -> User:
        if current_user.role != required_role:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, 
                detail=f"Permission denied. Required role: {required_role.value}"
            )
        return current_user 
    return wrapper