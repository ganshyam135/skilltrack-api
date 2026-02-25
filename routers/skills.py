from fastapi import APIRouter, Depends, HTTPException, status, Path
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

@router.get("/", status_code=status.HTTP_200_OK)
async def read_all_skills(
        db: db_dependency,
        user: user_dependency
):
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication failed")
    return db.query(Skills).filter(Skills.owner_id == user.id).all()

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

@router.get("/{skill_id}", status_code=status.HTTP_200_OK)
async def get_skill(
    db: db_dependency,
    user: user_dependency,
    skill_id: int = Path(gt=0)
):
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication failed")
    
    skill = db.query(Skills).filter(Skills.id == skill_id, Skills.owner_id == user.id).first()

    if skill is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Skill not found")
    
    return skill

@router.delete("/{skill_id}", status_code=status.HTTP_200_OK)
async def delete_skill(
    db: db_dependency,
    user: user_dependency,
    skill_id: int = Path(gt=0)
):
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication failed")
    
    skill = db.query(Skills).filter(Skills.id == skill_id, Skills.owner_id == user.id).first()

    if skill is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Skill not found")
    
    db.delete(skill)
    db.commit()