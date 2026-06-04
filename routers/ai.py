from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import Annotated
import google.generativeai as genai
from sqlalchemy import func
from datetime import datetime, timedelta

from config import get_settings
from database import SessionLocal
from models import Users, Sessions, Skills, Goals
from routers.auth import get_current_user

router = APIRouter(
    prefix="/ai",
    tags=["AI"]
)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


db_dependency = Annotated[Session, Depends(get_db)]
user_dependency = Annotated[Users, Depends(get_current_user)]


def get_gemini_model():
    settings = get_settings()

    if not settings.gemini_api_key:
        raise HTTPException(
            status_code=503,
            detail="GEMINI_API_KEY is missing. Add it to .env and restart Docker.",
        )

    genai.configure(api_key=settings.gemini_api_key)
    return genai.GenerativeModel("gemini-2.5-flash")


@router.post("/test")
async def test_ai(
    user: user_dependency
):

    try:
        model = get_gemini_model()

        response = model.generate_content(
            "Give me one study tip for students."
        )

        return {
            "response": response.text
        }

    except Exception as e:
        if isinstance(e, HTTPException):
            raise e

        raise HTTPException(
            status_code=500,
            detail=str(e)
        )


@router.post("/study-report")
async def generate_study_report(
    db: db_dependency,
    user: user_dependency
):

    try:

        total_minutes = (
            db.query(func.sum(Sessions.duration))
            .filter(Sessions.owner_id == user.id)
            .scalar()
        ) or 0

        total_hours = round(total_minutes / 60, 1)

        recent_sessions = (
            db.query(Sessions)
            .filter(Sessions.owner_id == user.id)
            .order_by(Sessions.created_at.desc())
            .limit(5)
            .all()
        )

        goals = (
            db.query(Goals)
            .filter(Goals.owner_id == user.id)
            .all()
        )

        skills = (
            db.query(Skills)
            .filter(Skills.owner_id == user.id)
            .all()
        )

        session_summary = []

        for session in recent_sessions:
            session_summary.append(
                f"{session.duration} mins - {session.notes}"
            )

        goal_summary = []

        for goal in goals:
            goal_summary.append(
                f"{goal.title} ({goal.target_hours} hours target)"
            )

        skill_summary = []

        for skill in skills:
            skill_summary.append(skill.name)

        prompt = f"""
        You are an AI learning coach.

        Analyze this user's learning data and provide:

        1. Learning summary
        2. Strengths
        3. Weaknesses
        4. Actionable recommendations

        Total Study Hours:
        {total_hours}

        Skills:
        {skill_summary}

        Goals:
        {goal_summary}

        Recent Sessions:
        {session_summary}

        Keep the response concise and practical.
        """

        model = get_gemini_model()
        response = model.generate_content(prompt)

        return {
            "report": response.text
        }

    except Exception as e:

        raise HTTPException(
            status_code=500,
            detail=str(e)
        )