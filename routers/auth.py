from fastapi import APIRouter
from pydantic import BaseModel
from database import SessionLocal
from models import Users
from sqlalchemy.orm import Session
from fastapi import Depends, HTTPException
from passlib.context import CryptContext
from typing import Annotated
from starlette import status


router = APIRouter(
    prefix="/auth",
    tags=["auth"]
)   

bcrypt_context = CryptContext(
    schemes=['bcrypt'], 
    deprecated='auto'
)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

db_dependency = Annotated[Session, Depends(get_db)]

class CreateUserRequest(BaseModel):
    username: str
    email: str
    password: str

@router.post("/register", status_code=status.HTTP_201_CREATED)
async def create_user(
    db: db_dependency,
    create_user_request: CreateUserRequest
):
    create_user_model = Users(
        username = create_user_request.username,
        email = create_user_request.email,
        hashed_password = bcrypt_context.hash(create_user_request.password),
        is_active = True
    )

    db.add(create_user_model)
    db.commit()

