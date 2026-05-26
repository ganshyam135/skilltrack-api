from fastapi import FastAPI
import models
from database import engine
from routers import auth, skills, topics, sessions, analytics, goals

from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],

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

@app.get("/")
async def root():
    return {"message": "SkillTrack API is running"}

@app.get("/health")
async def health_check():
    return {"status": "healthy"}