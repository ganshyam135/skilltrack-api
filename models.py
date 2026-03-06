from database import Base
from sqlalchemy import Column, Integer, String, Boolean, ForeignKey, DateTime
from sqlalchemy.orm import relationship
from datetime import datetime, UTC
from sqlalchemy import DateTime


class Users(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    is_active = Column(Boolean, default=True)

    skills = relationship("Skills", back_populates="owner")


class Skills(Base):
    __tablename__ = "skills"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    description = Column(String, nullable=True)

    owner_id = Column(Integer, ForeignKey("users.id"), index=True)
    created_at = Column(DateTime, default=lambda: datetime.now(UTC))

    owner = relationship("Users", back_populates="skills")


class Topics(Base):
    __tablename__ = "topics"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, nullable=False)
    description = Column(String, nullable=True)

    skill_id = Column(Integer, ForeignKey("skills.id"))
    owner_id = Column(Integer, ForeignKey("users.id"))


class Sessions(Base):
    __tablename__ = "sessions"

    id = Column(Integer, primary_key=True, index=True)

    duration = Column(Integer, nullable=False) #minutes
    notes = Column(String, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)

    topics_id = Column(Integer, ForeignKey("topics.id"), index=True)
    skill_id = Column(Integer, ForeignKey("skills.id"), index=True)
    owner_id = Column(Integer, ForeignKey("users.id"), index=True)
