# SkillTrack API

SkillTrack is a production-style backend API built with FastAPI that helps users track their learning progress by organizing **skills, topics, and study sessions**.

The system provides authentication, analytics, caching, and containerized infrastructure.

---

# Features

User Authentication
- JWT-based authentication
- Secure password hashing
- Protected routes

Skill Management
- Create skills
- Update skills
- Delete skills
- Paginated skill listing

Topic Management
- Topics linked to skills
- Full CRUD support

Study Session Tracking
- Track learning sessions
- Associate sessions with topics

Analytics
- Total study time
- Skill time breakdown
- Topic time breakdown
- Weekly study summary

Performance Features
- Redis caching
- Pagination
- Database indexing

Infrastructure
- Docker containerization
- PostgreSQL database
- Redis caching layer
- Alembic migrations

---

# Tech Stack

Backend
- FastAPI
- Python

Database
- PostgreSQL
- SQLAlchemy ORM

Caching
- Redis

Infrastructure
- Docker
- Docker Compose

Database Migration
- Alembic

Authentication
- JWT (JSON Web Tokens)

Testing
- Pytest

---

# Project Architecture
