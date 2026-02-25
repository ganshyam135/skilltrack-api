from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from typing import Annotated
from sqlalchemy.orm import Session

from database import SessionLocal
from models import Skills, Users
from routers.auth import get_current_user

router = APIRouter(
    prefix="/skills",
    tags=["skills"]
)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

db_dependency = Annotated[Session, Depends(get_db)]
user_dependency = Annotated[Users, Depends(get_current_user)]

class CreateSkillRequest(BaseModel):
    name: str
    description: str | None = None

@router.post("/", status_code=status.HTTP_201_CREATED)
async def create_skill(
    db: db_dependency,
    user: user_dependency,
    skill_request: CreateSkillRequest
):
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication failed")
    
    skill_model = Skills(
        name=skill_request.name,
        description=skill_request.description,
        owner_id=user.id
    )

    db.add(skill_model)
    db.commit()