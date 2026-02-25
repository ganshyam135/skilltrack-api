from fastapi import FastAPI
import models
from database import engine
from routers import auth, skills, topics

app = FastAPI()

models.Base.metadata.create_all(bind=engine)

app.include_router(auth.router)
app.include_router(skills.router)
app.include_router(topics.router)

@app.get("/")
async def root():
    return {"message": "SkillTrack API is running"}