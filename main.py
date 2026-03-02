from fastapi import FastAPI
import models
from database import engine
from routers import auth, skills, topics, sessions

app = FastAPI()


app.include_router(auth.router)
app.include_router(skills.router)
app.include_router(topics.router)
app.include_router(sessions.router)

@app.get("/")
async def root():
    return {"message": "SkillTrack API is running"}