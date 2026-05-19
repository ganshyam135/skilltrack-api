from fastapi import APIRouter, Depends, HTTPException, status
from typing import Annotated
from sqlalchemy.orm import Session
from sqlalchemy import func
from datetime import date, datetime, timedelta, timezone

from database import SessionLocal
from models import Sessions, Users, Skills
from routers.auth import get_current_user

from fastapi import Path

router = APIRouter(
    prefix="/analytics",
    tags=["analytics"]
)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

db_dependency = Annotated[Session, Depends(get_db)]
user_dependency = Annotated[Users, Depends(get_current_user)]


#total time endpoint
@router.get("/total-time", status_code=status.HTTP_200_OK)
async def get_total_learning_time(
    db: db_dependency,
    user: user_dependency
):

    if user is None:
        raise HTTPException(status_code=401, detail="Authentication failed")

    total_time = db.query(func.sum(Sessions.duration)).filter(
        Sessions.owner_id == user.id
    ).scalar()

    return {
        "total_minutes": total_time or 0
    }


#time per skill endpoint
@router.get("/skill-time/{skill_id}", status_code=status.HTTP_200_OK)
async def get_skill_learning_time(
    db: db_dependency,
    user: user_dependency,
    skill_id: int = Path(gt=0)
):

    if user is None:
        raise HTTPException(status_code=401, detail="Authentication failed")

    total_time = db.query(func.sum(Sessions.duration)).filter(
        Sessions.owner_id == user.id,
        Sessions.skill_id == skill_id
    ).scalar()

    return {
        "skill_id": skill_id,
        "total_minutes": total_time or 0
    }



@router.get("/topic-time/{topic_id}", status_code=status.HTTP_200_OK)
async def get_topic_learning_time(
    db: db_dependency,
    user: user_dependency,
    topic_id: int = Path(gt=0)
):

    if user is None:
        raise HTTPException(status_code=401, detail="Authentication failed")

    total_time = db.query(func.sum(Sessions.duration)).filter(
        Sessions.owner_id == user.id,
        Sessions.topics_id == topic_id
    ).scalar()

    return {
        "topic_id": topic_id,
        "total_minutes": total_time or 0
    }


#skill breakdown endpoint
@router.get("/skill-breakdown", status_code=status.HTTP_200_OK)
async def get_skill_breakdown(
    db: db_dependency,
    user: user_dependency
):

    if user is None:
        raise HTTPException(status_code=401, detail="Authentication failed")

    results = (
        db.query(
            Skills.name,
            func.sum(Sessions.duration).label("total_minutes")
        )
        .join(Sessions, Sessions.skill_id == Skills.id)
        .filter(Sessions.owner_id == user.id)
        .group_by(Skills.name)
        .all()
    )

    return [
        {"skill": skill, "minutes": minutes}
        for skill, minutes in results
    ]


#weekly summary endpoint
@router.get("/weekly-summary", status_code=status.HTTP_200_OK)
async def get_weekly_summary(
    db: db_dependency,
    user: user_dependency
):
    if user is None:
        raise HTTPException(status_code=401, detail="Authentication failed")
    
    results = (
        db.query(func.date(Sessions.created_at).label("date"),
                 func.sum(Sessions.duration).label("total_minutes")
        )
        .filter(Sessions.owner_id == user.id)
        .group_by(func.date(Sessions.created_at))
        .order_by(func.date(Sessions.created_at))
        .all()
    )

    return [
        {'date': str(date), "minutes": minutes}
        for date, minutes in results
    ]


@router.get("/streak")
async def get_streak(
    db: db_dependency,
    user: user_dependency
):
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed"
        )
    
    sessions = (
        db.query(Sessions)
        .filter(Sessions.owner_id == user.id)
        .order_by(Sessions.created_at.asc())
        .all()
    )

    if not sessions:
        return{
            "current_streak": 0,
            "longest_streak": 0,
            "last_study_date": None
        }
    
    study_dates = sorted(
        list(set(session.created_at.date() for session in sessions))
    )

    longest_streak = 1
    current_streak = 1

    for i in range(1, len(study_dates)):
        if study_dates[i] == study_dates[i - 1] + timedelta(days=1):
            current_streak += 1
            longest_streak = max(longest_streak, current_streak)
        else: 
            current_streak = 1

    today = datetime.now(timezone.utc).date()

    latest_date = study_dates[-1]

    if latest_date != today and latest_date != today - timedelta(days=1):
        current_streak = 0

    return {
        "current_streak": current_streak,
        "longest_streak": longest_streak,
        "last_study_date": latest_date
    }