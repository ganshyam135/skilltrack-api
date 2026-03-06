from fastapi import APIRouter, Depends, HTTPException, status, Path, Query
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
    user: user_dependency,
    limit: int = Query(10, le=100),
    offset: int = Query(0, ge=0)
):
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication failed")
    
    return (db.query(Sessions)
            .filter(Sessions.owner_id == user.id)
            .offset(offset)
            .limit(limit)
            .all()
            )

    

#get session by id
@router.get("/{session_id}", status_code=status.HTTP_200_OK)
async def get_session(
    db: db_dependency,
    user: user_dependency,
    session_id: int = Path(gt=0)
):

    if user is None:
        raise HTTPException(status_code=401, detail="Authentication failed")

    session = db.query(Sessions).filter(
        Sessions.id == session_id,
        Sessions.owner_id == user.id
    ).first()

    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")

    return session

#update session
@router.put("/{session_id}", status_code=status.HTTP_204_NO_CONTENT)
async def update_session(
    db: db_dependency,
    user: user_dependency,
    session_id: int = Path(gt=0),
    session_request: CreateSessionRequest = None
):

    if user is None:
        raise HTTPException(status_code=401, detail="Authentication failed")

    session = db.query(Sessions).filter(
        Sessions.id == session_id,
        Sessions.owner_id == user.id
    ).first()

    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")

    session.duration = session_request.duration
    session.notes = session_request.notes
    session.topic_id = session_request.topic_id
    session.skill_id = session_request.skill_id

    db.commit()

#delete session
@router.delete("/{session_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_session(
    db: db_dependency,
    user: user_dependency,
    session_id: int = Path(gt=0)
    ):

    if user is None:
        raise HTTPException(status_code=401, detail="Authentication failed")

    session = db.query(Sessions).filter(
        Sessions.id == session_id,
        Sessions.owner_id == user.id
    ).first()

    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")

    db.delete(session)
    db.commit()