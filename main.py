from fastapi import FastAPI
import models
from database import engine
from routers import auth, skills, topics, sessions, analytics, goals, ai
from config import get_settings

from fastapi.middleware.cors import CORSMiddleware

settings = get_settings()

app = FastAPI(
    title=settings.app_name,
    version="1.0.0",
    description="Learning analytics API for skills, topics, goals, and study sessions.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


app.include_router(auth.router)
app.include_router(skills.router)
app.include_router(topics.router)
app.include_router(sessions.router)
app.include_router(analytics.router)
app.include_router(goals.router)
app.include_router(ai.router)

@app.get("/")
async def root():
    return {
        "message": "SkillTrack API is running",
        "environment": settings.app_environment,
        "docs": "/docs",
    }

@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": settings.app_name}
