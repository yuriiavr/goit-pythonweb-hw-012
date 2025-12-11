import os
from fastapi import FastAPI, Depends, HTTPException, status, Query, UploadFile, File, Request
from sqlalchemy.orm import Session
from typing import List, Optional
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from redis.asyncio import Redis
from fastapi_limiter import FastAPILimiter
from fastapi_limiter.depends import RateLimiter

from database import engine, get_db
from models import Base, Role
import crud, models, schemas
from auth import auth_service, role_required
from email_service import send_email, send_reset_email
from cloudinary_service import upload_avatar

Base.metadata.create_all(bind=engine)

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

@app.on_event("startup")
async def startup():
    try:
        r = await Redis(host=os.environ.get("REDIS_HOST"), port=int(os.environ.get("REDIS_PORT")), db=0)
        await FastAPILimiter.init(r)
    except Exception as e:
        print(f"Could not initialize Redis for RateLimiter: {e}")

@app.post("/api/auth/signup", response_model=schemas.UserResponse, status_code=status.HTTP_201_CREATED, tags=["Auth"])
async def signup(body: schemas.UserCreate, request: Request, db: Session = Depends(get_db)):
    user = crud.get_user_by_email(db, body.email)
    if user:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Account already exists")
    new_user = crud.create_user(db, body)
    await send_email(new_user.email, new_user.username, request.base_url)
    return new_user

@app.post("/api/auth/login", response_model=schemas.Token, tags=["Auth"])
async def login(body: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = crud.get_user_by_email(db, body.username)
    if user is None or not auth_service.verify_password(body.password, user.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    if not user.confirmed:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Email not confirmed")
    
    access_token = auth_service.create_access_token(data={"sub": user.email})
    refresh_token = auth_service.create_refresh_token(data={"sub": user.email})
    crud.update_token(db, user, refresh_token)
    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}

@app.get('/api/auth/refresh_token', response_model=schemas.Token, tags=['Auth'])
async def refresh_token(credentials: str = Depends(auth_service.decode_refresh_token), db: Session = Depends(get_db)):
    user = auth_service.get_user_by_email(credentials, db)
    if user.refresh_token is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")
    
    access_token = auth_service.create_access_token(data={"sub": credentials})
    refresh_token = auth_service.create_refresh_token(data={"sub": credentials})
    crud.update_token(db, user, refresh_token)
    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}

@app.get('/auth/confirmed_email/{token}', tags=["Auth"])
async def confirmed_email(token: str, db: Session = Depends(get_db)):
    email = auth_service.get_email_from_token(token)
    user = crud.get_user_by_email(db, email)
    if user is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Verification error")
    if user.confirmed:
        return {"message": "Your email is already confirmed"}
    user.confirmed = True
    db.commit()
    return {"message": "Email confirmed"}

@app.post("/api/auth/request_email", tags=["Auth"])
async def request_email(body: schemas.RequestEmail, request: Request, db: Session = Depends(get_db)):
    user = crud.get_user_by_email(db, body.email)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    if user.confirmed:
        return {"message": "Your email is already confirmed"}
    
    await send_email(user.email, user.username, request.base_url)
    return {"message": "Confirmation email sent"}

# Новий маршрут: Запит на скидання пароля
@app.post("/api/auth/request_reset_password", status_code=status.HTTP_200_OK, tags=["Auth"])
async def request_reset_password(body: schemas.RequestEmail, request: Request, db: Session = Depends(get_db)):
    user = crud.get_user_by_email(db, body.email)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    
    await send_reset_email(user.email, user.username, request.base_url)
    return {"message": "Password reset email sent"}

# Новий маршрут: Встановлення нового пароля
@app.post("/api/auth/reset_password/{token}", status_code=status.HTTP_200_OK, tags=["Auth"])
async def reset_password(token: str, body: schemas.ResetPassword, db: Session = Depends(get_db)):
    email = auth_service.get_email_from_reset_token(token)
    user = crud.get_user_by_email(db, email)
    if user is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Reset error")
    
    crud.update_password(db, user, body.new_password)
    return {"message": "Password updated successfully"}

# User routes
@app.get("/users/me", response_model=schemas.UserResponse, tags=["User"])
async def read_users_me(current_user: models.User = Depends(auth_service.get_current_user)):
    return current_user

# Оновлений маршрут: зміна аватара лише для адміністраторів
@app.patch("/users/avatar", response_model=schemas.UserResponse, tags=["User"])
async def update_avatar(
    file: UploadFile = File(), 
    db: Session = Depends(get_db), 
    current_user: models.User = Depends(role_required(Role.admin))
):
    if not current_user.confirmed:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Email not confirmed")
    
    public_id = f"contacts/{current_user.email}"
    r = upload_avatar(file.file, public_id)
    user = crud.update_user_avatar(db, current_user, r)
    
    redis_client = await auth_service.get_redis_client()
    await redis_client.delete(f"user:{current_user.email}")
    
    return user

@app.post("/api/contacts", response_model=schemas.ContactResponse, status_code=status.HTTP_201_CREATED, tags=["Contacts"], dependencies=[Depends(RateLimiter(times=2, seconds=5))])
def create_contact(contact: schemas.ContactCreate, db: Session = Depends(get_db), current_user: models.User = Depends(auth_service.get_current_user)):
    if not current_user.confirmed:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Email not confirmed")
    
    existing_contact = crud.get_contact_by_email_for_user(db, contact.email, current_user.id)
    if existing_contact:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Contact with this email already exists")
    
    return crud.create_contact(db, contact, current_user.id)

@app.get("/api/contacts", response_model=List[schemas.ContactResponse], tags=["Contacts"])
def read_contacts(skip: int = 0, limit: int = 10, db: Session = Depends(get_db), current_user: models.User = Depends(auth_service.get_current_user)):
    if not current_user.confirmed:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Email not confirmed")
    
    contacts = crud.get_contacts(db, current_user.id, skip=skip, limit=limit)
    return contacts

@app.get("/api/contacts/{contact_id}", response_model=schemas.ContactResponse, tags=["Contacts"])
def read_contact(contact_id: int, db: Session = Depends(get_db), current_user: models.User = Depends(auth_service.get_current_user)):
    if not current_user.confirmed:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Email not confirmed")
    
    contact = crud.get_contact(db, contact_id, current_user.id)
    if contact is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Contact not found or does not belong to user")
    return contact

@app.put("/api/contacts/{contact_id}", response_model=schemas.ContactResponse, tags=["Contacts"])
def update_contact(contact_id: int, contact: schemas.ContactUpdate, db: Session = Depends(get_db), current_user: models.User = Depends(auth_service.get_current_user)):
    if not current_user.confirmed:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Email not confirmed")
    
    db_contact = crud.get_contact(db, contact_id, current_user.id)
    if db_contact is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Contact not found or does not belong to user")
    
    updated_contact = crud.update_contact(db, db_contact, contact)
    return updated_contact

@app.delete("/api/contacts/{contact_id}", tags=["Contacts"])
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
    
    contacts = crud.get_upcoming_birthdays(db, current_user.id)
    return contacts