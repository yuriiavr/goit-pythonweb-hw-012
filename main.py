import os
from fastapi import FastAPI, Depends, HTTPException, status, Query, UploadFile, File, Request, BackgroundTasks
from sqlalchemy.orm import Session
from typing import List, Optional
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from redis.asyncio import Redis
from fastapi_limiter import FastAPILimiter
from fastapi_limiter.depends import RateLimiter
from pydantic import Field

from database import engine, get_db
from models import Base, Role
import crud, models, schemas
from auth import auth_service, role_required
from email_service import send_email, send_reset_email
from cloudinary_service import upload_avatar
import secrets
import string

app = FastAPI(
    title="Contacts REST API",
    description="API для управління контактами з FastAPI, SQLAlchemy та JWT-авторизацією.",
    version="1.0.2"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/", tags=["Root"]) 
def root(): 
    return {"message": "Welcome to the Contacts REST API!"}

@app.on_event("startup")
async def startup():
    try:
        redis_host = os.environ.get("REDIS_HOST", "localhost")
        redis_port = int(os.environ.get("REDIS_PORT", 6379))
        r = await Redis(host=redis_host, port=redis_port, db=0)
        await FastAPILimiter.init(r)
    except Exception as e:
        print(f"Failed to connect to Redis: {e}")

@app.post("/api/auth/signup", response_model=schemas.UserResponse, status_code=status.HTTP_201_CREATED, tags=["Auth"])
async def signup(body: schemas.UserCreate, background_tasks: BackgroundTasks, request: Request, db: Session = Depends(get_db)):
    """
    Реєстрація нового користувача в системі.

    :param body: Дані для створення користувача (email, username, password).
    :param background_tasks: Фонове завдання для відправки листа підтвердження.
    :param request: Об'єкт запиту для отримання base_url.
    :param db: Сесія бази даних SQLAlchemy.
    :return: Об'єкт створеного користувача.
    :raises HTTPException: 409 Conflict, якщо email вже зареєстрований.
    """
    user = crud.get_user_by_email(db, body.email)
    if user:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Account already exists")
    
    new_user = crud.create_user(db, body)
    
    background_tasks.add_task(send_email, new_user.email, new_user.username, request.base_url)
    
    return new_user

@app.post("/api/auth/login", tags=["Auth"])
def login(body: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = crud.get_user_by_email(db, body.username)
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    if not user.confirmed:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Email not confirmed", 
            headers={"WWW-Authenticate": "Bearer"}
        )
    if not auth_service.verify_password(body.password, user.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    if not user.confirmed:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Email not confirmed")
    
    access_token = auth_service.create_access_token(data={"sub": user.email, "scope": "access_token"})
    refresh_token = auth_service.create_refresh_token(data={"sub": user.email, "scope": "refresh_token"})
    crud.update_token(db, user, refresh_token)
    
    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}

@app.get("/api/auth/refresh_token", tags=["Auth"])
def refresh_token(credentials: str = Depends(auth_service.oauth2_scheme), db: Session = Depends(get_db)):
    email = auth_service.decode_refresh_token(credentials)
    user = crud.get_user_by_email(db, email)
    
    if user.refresh_token != credentials:
        crud.update_token(db, user, None)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")

    access_token = auth_service.create_access_token(data={"sub": email, "scope": "access_token"})
    refresh_token = auth_service.create_refresh_token(data={"sub": email, "scope": "refresh_token"})
    crud.update_token(db, user, refresh_token)
    
    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}

@app.get("/api/auth/confirmed_email/{token}", tags=["Auth"])
def confirmed_email(token: str, db: Session = Depends(get_db)):
    email = auth_service.decode_email_token(token)
    user = crud.get_user_by_email(db, email)
    
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    if user.confirmed:
        return {"message": "Your email is already confirmed"}
        
    crud.confirm_email(db, email)
    return {"message": "Email confirmed successfully"}

@app.post("/api/auth/request_email", status_code=status.HTTP_200_OK, tags=["Auth"])
async def request_email(body: schemas.RequestEmail, background_tasks: BackgroundTasks, request: Request, db: Session = Depends(get_db)):
    user = crud.get_user_by_email(db, body.email)
    
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    if user.confirmed:
        return {"message": "Your email is already confirmed"}

    background_tasks.add_task(send_email, user.email, user.username, request.base_url)
    return {"message": "Email confirmation sent successfully"}

@app.post("/api/auth/request_reset_password", status_code=status.HTTP_200_OK, tags=["Auth"])
async def request_reset_password(
    body: schemas.RequestEmail, 
    background_tasks: BackgroundTasks, 
    request: Request, 
    db: Session = Depends(get_db)
):
    user = crud.get_user_by_email(db, body.email)
    
    if user:
        host = str(request.base_url)
        background_tasks.add_task(send_reset_email, user.email, user.username, host)
    
    return {"message": "Якщо користувач існує, лист для скидання пароля буде надіслано."}

@app.get("/users/me", response_model=schemas.UserResponse, tags=["User"])
def read_users_me(current_user: models.User = Depends(auth_service.get_current_user)):
    return current_user

@app.patch("/users/avatar", response_model=schemas.UserResponse, tags=["User"])
async def update_avatar(
    file: UploadFile = File(...), 
    db: Session = Depends(get_db), 
    current_user: models.User = Depends(role_required(Role.admin))
):
    if not current_user.confirmed:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Email not confirmed")
        
    file_content = await file.read()
    public_id = f"contacts/{current_user.email}"
    avatar_url = upload_avatar(file_content, public_id)
    
    current_user.avatar = avatar_url
    db.commit()
    db.refresh(current_user)
    
    redis_client = await auth_service.get_redis_client()
    await redis_client.delete(f"user:{current_user.email}")
    
    return current_user

@app.put("/users/{user_id}/role", response_model=schemas.UserResponse, tags=["Users"])
def update_user_role(
    user_id: int, 
    new_role: schemas.UserRoleUpdate, 
    db: Session = Depends(get_db), 
    admin_user: models.User = Depends(role_required(models.Role.admin)) 
):
    user = crud.get_user_by_id(db, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    updated_user = crud.update_user_role(db, user, new_role.role)
    
    return updated_user

@app.post("/contacts/", response_model=schemas.ContactResponse, status_code=status.HTTP_201_CREATED, tags=["Contacts"], dependencies=[Depends(RateLimiter(times=2, seconds=5))])
def create_contact(contact: schemas.ContactCreate, db: Session = Depends(get_db), current_user: models.User = Depends(auth_service.get_current_user)):
    if not current_user.confirmed:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Email not confirmed")
        
    db_contact = crud.get_contact_by_email_for_user(db, contact.email, current_user.id)
    if db_contact:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Contact with this email already exists")

    return crud.create_contact(db, contact, current_user.id)

@app.get("/contacts/", response_model=List[schemas.ContactResponse], tags=["Contacts"])
def read_contacts(skip: int = 0, limit: int = 100, db: Session = Depends(get_db), current_user: models.User = Depends(auth_service.get_current_user)):
    if not current_user.confirmed:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Email not confirmed")
        
    contacts = crud.get_contacts(db, skip=skip, limit=limit, user_id=current_user.id)
    return contacts

@app.get("/contacts/{contact_id}", response_model=schemas.ContactResponse, tags=["Contacts"])
def read_contact(contact_id: int, db: Session = Depends(get_db), current_user: models.User = Depends(auth_service.get_current_user)):
    if not current_user.confirmed:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Email not confirmed")
        
    contact = crud.get_contact(db, contact_id, user_id=current_user.id)
    if contact is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Contact not found or does not belong to user")
    return contact

@app.put("/contacts/{contact_id}", response_model=schemas.ContactResponse, tags=["Contacts"])
def update_contact(contact_id: int, contact: schemas.ContactUpdate, db: Session = Depends(get_db), current_user: models.User = Depends(auth_service.get_current_user)):
    if not current_user.confirmed:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Email not confirmed")
        
    db_contact = crud.get_contact(db, contact_id, user_id=current_user.id)
    if db_contact is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Contact not found or does not belong to user")
    
    return crud.update_contact(db, db_contact, contact)

@app.delete("/contacts/{contact_id}", status_code=status.HTTP_200_OK, tags=["Contacts"])
def delete_contact(contact_id: int, db: Session = Depends(get_db), current_user: models.User = Depends(auth_service.get_current_user)):
    if not current_user.confirmed:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Email not confirmed")

    deleted_contact = crud.delete_contact(db, contact_id, user_id=current_user.id)
    if deleted_contact is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Contact not found or does not belong to user")
    return {"message": "Contact deleted successfully"}

@app.get("/contacts/search/", response_model=List[schemas.ContactResponse], tags=["Additional"])
def search_contacts(
    query: Optional[str] = Query(None, description="Пошуковий запит за іменем, прізвищем чи електронною поштою"), 
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth_service.get_current_user)
):
    if not current_user.confirmed:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Email not confirmed")

    if query:
        contacts = crud.search_contacts(db, query, user_id=current_user.id)
        return contacts
    return crud.get_contacts(db, user_id=current_user.id)

@app.get("/contacts/birthdays/", response_model=List[schemas.ContactResponse], tags=["Additional"])
def upcoming_birthdays(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth_service.get_current_user)
):
    if not current_user.confirmed:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Email not confirmed")
        
    contacts = crud.get_upcoming_birthdays(db, user_id=current_user.id)
    return contacts

@app.post("/api/auth/reset_password", status_code=status.HTTP_200_OK, tags=["Auth"]) 
def reset_password(
    body: schemas.ResetPassword, 
    token: str = Query(..., description="Токен для скидання пароля з листа"), 
    db: Session = Depends(get_db)
):
    try:
        email = auth_service.decode_reset_token(token)
    except HTTPException:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")

    user = crud.get_user_by_email(db, email)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    crud.update_password(db, user, body.new_password)
    
    return {"message": "Password updated successfully. You can now login with your new password."}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)