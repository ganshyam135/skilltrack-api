from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import Annotated
import google.generativeai as genai

from config import get_settings
from database import SessionLocal
from models import Users
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
