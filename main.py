from fastapi import FastAPI
import models
from database import engine
from routers import auth, skills, topics, sessions, analytics

app = FastAPI()


app.include_router(auth.router)
app.include_router(skills.router)
app.include_router(topics.router)
app.include_router(sessions.router)
app.include_router(analytics.router)

@app.get("/")
async def root():
    return {"message": "SkillTrack API is running"}

@app.get("/health")
async def health_check():
    return {"status": "healthy"}