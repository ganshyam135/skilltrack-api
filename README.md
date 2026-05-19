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

Client
↓
FastAPI API Server
↓
SQLAlchemy ORM
↓
PostgreSQL Database

Caching Layer
↓
Redis

Infrastructure
↓
Docker Containers

---

# Folder Structure

skilltrack-api

alembic/
routers/
auth.py
skills.py
topics.py
sessions.py
analytics.py

database.py
models.py
schemas.py
redis_client.py
main.py

Dockerfile
docker-compose.yml
requirements.txt

---

# Installation

Clone the repository

Create environment file
.env

Example:
POSTGRES_USER=postgres
POSTGRES_PASSWORD=password
POSTGRES_DB=skilltrack

DATABASE_URL=postgresql://postgres:password@db:5432/skilltrack

---

# Running with Docker

Start the full stack
docker compose up --build

Services started:
skilltrack-api
skilltrack-db
skilltrack-redis

API available at:
http://localhost:8000/docs

---

# Database Migrations

Apply migrations
docker compose exec api alembic upgrade head

Create migration
alembic revision --autogenerate -m "message"

---

# Example Endpoints

Authentication

POST /auth/register
POST /auth/login

Skills
GET /skills
POST /skills
PUT /skills/{id}
DELETE /skills/{id}

Topics
GET /topics
POST /topics

Sessions
POST /sessions
GET /sessions

Analytics
GET /analytics/total-time
GET /analytics/skill-breakdown
GET /analytics/topic-breakdown
GET /analytics/weekly-summary

---

# Health Check

GET /health

Used for infrastructure monitoring.

---

# Learning Goals

This project demonstrates backend engineering concepts such as:

- REST API design
- Authentication systems
- Database schema design
- Redis caching
- Docker containerization
- Database migrations
- Performance optimization

---

# Future Improvements

Possible future enhancements:

- Rate limiting
- Background job processing
- Microservices architecture
- Distributed caching
- Kubernetes deployment

---

# Author

Ganshyam Suthar
