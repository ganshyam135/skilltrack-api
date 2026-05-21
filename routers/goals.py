from fastapi import APIRouter, Depends, HTTPException, status, Path
from sqlalchemy.orm import Session
from typing import Annotated
from pydantic import BaseModel
from datetime import datetime

from database import SessionLocal
from models import Goals, Users
from routers.auth import get_current_user

router = APIRouter(
    prefix="/goals",
    tags=["goals"]
)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


db_dependency = Annotated[Session, Depends(get_db)]
user_dependency = Annotated[Users, Depends(get_current_user)]


class GoalRequest(BaseModel):
    title: str
    target_hours: int
    start_date: datetime
    end_date: datetime


@router.post("/", status_code=status.HTTP_201_CREATED)
async def create_goal(
    db: db_dependency,
    user: user_dependency,
    goal_request: GoalRequest
):

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed"
        )

    goal = Goals(
        title=goal_request.title,
        target_hours=goal_request.target_hours,
        start_date=goal_request.start_date,
        end_date=goal_request.end_date,
        owner_id=user.id
    )

    db.add(goal)
    db.commit()


@router.get("/", status_code=status.HTTP_200_OK)
async def get_goals(
    db: db_dependency,
    user: user_dependency
):

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed"
        )

    return db.query(Goals).filter(
        Goals.owner_id == user.id
    ).all()


@router.delete("/{goal_id}", status_code=status.HTTP_200_OK)
async def delete_goal(
    db: db_dependency,
    user: user_dependency,
    goal_id: int = Path(gt=0)
):

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed"
        )

    goal = db.query(Goals).filter(
        Goals.id == goal_id,
        Goals.owner_id == user.id
    ).first()

    if goal is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Goal not found"
        )

    db.delete(goal)
    db.commit()