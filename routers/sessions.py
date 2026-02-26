from fastapi import APIRouter, Depends, HTTPException, status, Path
from pydantic import BaseModel
from typing import Annotated
from sqlalchemy.orm import Session

from database import SessionLocal
from models import Sessions, Topics, Skills, Users
from routers.auth import get_current_user

router = APIRouter(
    prefix="/sessions",
    tags=["sessions"]
)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

db_dependency = Annotated[Session, Depends(get_db)]
user_dependency = Annotated[Users, Depends(get_current_user)]


class CreateSessionRequest(BaseModel):
    duration: int
    notes: str | None = None
    topic_id: int
    skill_id: int


#create session
@router.post("/", status_code=status.HTTP_201_CREATED)
async def create_session(
    db: db_dependency,
    user: user_dependency,
    session_request: CreateSessionRequest
):
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication failed")
    
    skill = db.query(Skills).filter(
        Skills.id == session_request.skill_id, 
        Skills.owner_id == user.id
        ).first()
    
    if skill is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Skill not found")
    
    topic = db.query(Topics).filter(
        Skills.id == session_request.topic_id,
        Skills.owner_id == user.id
        ).first()
    
    if topic is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Topic not found")
    
    session = Sessions(
        duration = session_request.duration,
        notes = session_request.notes,
        topics_id = session_request.topic_id,
        skill_id = session_request.skill_id,
        owner_id = user.id
    )

    db.add(session)
    db.commit()


#get all sessions for the topic
@router.get("/", status_code=status.HTTP_200_OK)
async def get_sessions(
    db: db_dependency,
    user: user_dependency
):
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication failed")
    
    sessions = db.query(Sessions).filter(Sessions.owner_id == user.id).all()

    return sessions
