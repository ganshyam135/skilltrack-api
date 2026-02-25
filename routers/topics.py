from fastapi import APIRouter, Depends, HTTPException, status, Path
from pydantic import BaseModel
from typing import Annotated
from sqlalchemy.orm import Session

from database import SessionLocal
from models import Topics, Skills, Users
from routers.auth import get_current_user

router = APIRouter(
    prefix="/topics",
    tags=["topics"]
)

from fastapi import APIRouter, Depends, HTTPException, status, Path
from pydantic import BaseModel
from typing import Annotated
from sqlalchemy.orm import Session

from database import SessionLocal
from models import Topics, Skills, Users
from routers.auth import get_current_user

router = APIRouter(
    prefix="/topics",
    tags=["topics"]
)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

db_dependency = Annotated[Session, Depends(get_db)]
user_dependency = Annotated[Users, Depends(get_current_user)]

class CreateTopicRequest(BaseModel):
    title: str
    description: str | None = None
    skill_id: int


@router.post("/", status_code=status.HTTP_201_CREATED)
async def create_topic(
    db: db_dependency,
    user: user_dependency,
    topic_request: CreateTopicRequest
):
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication failed")

    skill = db.query(Skills).filter(Skills.id == topic_request.skill_id, Skills.owner_id == user.id).first()

    if skill is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Skill not found")
    
    topic = Topics(
        title=topic_request.title,
        description=topic_request.description,
        skill_id=topic_request.skill_id,
        owner_id=user.id
    )

    db.add(topic)
    db.commit()

@router.get("/", status_code=status.HTTP_200_OK)
async def read_all_topics(
    db: db_dependency,
    user: user_dependency
):
    if user is None:
        raise HTTPException(status_code=401, detail="Authentication failed")
    
    topics = db.query(Topics).filter(Topics.owner_id == user.id).all()

    return topics

@router.get("/{topic_id}", status_code=status.HTTP_200_OK)
async def get_topics(
    db: db_dependency,
    user: user_dependency,
    topic_id: int = Path(gt=0)
):
    if user is None:
        raise HTTPException(status_code=401, detail="Authentication failed")
    
    topic = db.query(Topics).filter(Topics.id == topic_id, Topics.owner_id == user.id).first()

    if topic is None:
        raise HTTPException(status_code=404, detail="Topic not found")
    
    return topic

@router.put("/{topic_id}", status_code=status.HTTP_200_OK)
async def update_topic(
    db: db_dependency,
    user: user_dependency,
    topic_id: int = Path(gt=0),
    topic_request: CreateTopicRequest = None
):
    if user is None:
        raise HTTPException(status_code=401, detail="Authentication failed")
    
    topic = db.query(Topics).filter(Topics.id == topic_id, Topics.owner_id == user.id).first()

    if topic is None:
        raise HTTPException(status_code=404, detail="Topic not found")
    
    skill = db.query(Skills).filter(Skills.id == topic_request.skill_id, Skills.owner_id == user.id).first()

    if skill is None:
        raise HTTPException(status_code=404, detail="Skill not found")
    
    topic.title = topic_request.title
    topic.description = topic_request.description
    topic.skill_id = topic_request.skill_id

    db.commit()

@router.delete("/{topic_id}", status_code=status.HTTP_200_OK)
async def delete_topic(
    db: db_dependency,
    user: user_dependency,
    topic_id: int = Path(gt=0)
):
    if user is None:
        raise HTTPException(status_code=401, detail="Authentication failed")
    
    topic = db.query(Topics).filter(Topics.id == topic_id, Topics.owner_id == user.id).first()

    if topic is None:
        raise HTTPException(status_code=404, detail="Topic not found")
    
    db.delete(topic)
    db.commit()
    

    