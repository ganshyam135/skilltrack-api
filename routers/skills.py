from fastapi import APIRouter, Depends, HTTPException, status, Path
from pydantic import BaseModel
from typing import Annotated
from sqlalchemy.orm import Session

from database import SessionLocal
from models import Skills, Users
from routers.auth import get_current_user

from schemas import SkillResponse
from typing import List

import json
from redis_client import redis_client

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

@router.get("/", status_code=status.HTTP_200_OK, response_model=List[SkillResponse])
async def read_all_skills(
        db: db_dependency,
        user: user_dependency
):
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication failed")
    
    cache_key = f"user_skills_{user.id}"

    cached_skills = redis_client.get(cache_key)

    if cached_skills:
        return json.loads(cached_skills)
    
    skills = db.query(Skills).filter(Skills.owner_id == user.id).all()
    
    skills_data = [
        {
            "id": s.id,
            "name": s.name,
            "description": s.description,
            "owner_id": s.owner_id,
            "created_at": s.created_at.isoformat()
        }
        for s in skills
    ]

    redis_client.set(cache_key, json.dumps(skills_data), ex=300)

    return skills_data

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
    redis_client.delete(f"user_skills_{user.id}")

@router.get("/{skill_id}", status_code=status.HTTP_200_OK, response_model=SkillResponse)
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

@router.put("/{skill_id}", status_code=status.HTTP_200_OK)
async def update_skill(
    db: db_dependency,
    user: user_dependency,
    skill_id: int = Path(gt=0),
    skill_request: CreateSkillRequest = None
):
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication failed")
    
    skill = db.query(Skills).filter(Skills.id == skill_id, Skills.owner_id == user.id).first()

    if skill is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Skill not found")
    
    skill.name = skill_request.name
    skill.description = skill_request.description

    db.commit()

@router.delete("/{skill_id}", status_code=status.HTTP_204_NO_CONTENT)
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