# railway.json
{
  "$schema": "https://railway.app/railway.schema.json",
  "build": {
    "builder": "NIXPACKS"
  },
  "deploy": {
    "startCommand": "uvicorn app.main:app --host 0.0.0.0 --port $PORT",
    "restartPolicyType": "ON_FAILURE",
    "restartPolicyMaxRetries": 10
  }
}

# nixpacks.toml
[phases.setup]
nixPkgs = ["python310", "postgresql"]

[phases.install]
cmds = ["pip install -r requirements.txt"]

[start]
cmd = "uvicorn app.main:app --host 0.0.0.0 --port $PORT"

# Procfile (alternative to railway.json)
web: uvicorn app.main:app --host 0.0.0.0 --port $PORT
worker: celery -A app.workers.celery_app worker --loglevel=info
beat: celery -A app.workers.celery_app beat --loglevel=info

# app/core/config.py (Updated for Railway)
from typing import List, Union, Optional
from pydantic_settings import BaseSettings
from pydantic import AnyHttpUrl, validator
import os

class Settings(BaseSettings):
    # API Settings
    API_V1_STR: str = "/api/v1"
    PROJECT_NAME: str = "ReferralVillage"
    
    # Railway provides PORT automatically
    PORT: int = int(os.getenv("PORT", 8000))
    
    # Security
    SECRET_KEY: str = os.getenv("SECRET_KEY", "your-secret-key-change-in-production")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 8  # 8 days
    
    # Database - Railway provides DATABASE_URL automatically
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL",
        "postgresql://postgres:password@localhost:5432/referralvillage"
    )
    
    # Railway PostgreSQL URLs start with postgresql://, not postgres://
    @validator("DATABASE_URL", pre=True)
    def validate_postgres_url(cls, v: str) -> str:
        if v.startswith("postgres://"):
            return v.replace("postgres://", "postgresql://", 1)
        return v
    
    # Redis - Railway provides REDIS_URL automatically
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379")
    
    # Railway Environment
    RAILWAY_ENVIRONMENT: Optional[str] = os.getenv("RAILWAY_ENVIRONMENT")
    RAILWAY_STATIC_URL: Optional[str] = os.getenv("RAILWAY_STATIC_URL")
    RAILWAY_GIT_COMMIT_SHA: Optional[str] = os.getenv("RAILWAY_GIT_COMMIT_SHA")
    
    # CORS - Updated for Railway deployments
    BACKEND_CORS_ORIGINS: List[AnyHttpUrl] = []
    
    @validator("BACKEND_CORS_ORIGINS", pre=True)
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> Union[List[str], str]:
        if isinstance(v, str) and not v.startswith("["):
            return [i.strip() for i in v.split(",")]
        elif isinstance(v, (list, str)):
            return v
        # Add Railway preview URLs automatically
        origins = []
        if os.getenv("RAILWAY_STATIC_URL"):
            origins.append(f"https://{os.getenv('RAILWAY_STATIC_URL')}")
        if os.getenv("RAILWAY_ENVIRONMENT") == "production":
            origins.extend([
                "https://referralvillage.com",
                "https://www.referralvillage.com",
                "https://app.referralvillage.com"
            ])
        else:
            origins.append("http://localhost:3000")
            origins.append("http://localhost:3001")
        return origins
    
    # Stripe
    STRIPE_SECRET_KEY: str = os.getenv("STRIPE_SECRET_KEY", "")
    STRIPE_WEBHOOK_SECRET: str = os.getenv("STRIPE_WEBHOOK_SECRET", "")
    
    # OpenAI (for AI matching)
    OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")
    
    # Frontend URL - Automatically set based on environment
    @property
    def FRONTEND_URL(self) -> str:
        if self.RAILWAY_ENVIRONMENT == "production":
            return "https://referralvillage.com"
        elif self.RAILWAY_STATIC_URL:
            return f"https://{self.RAILWAY_STATIC_URL}"
        return "http://localhost:3000"
    
    class Config:
        env_file = ".env"
        case_sensitive = True

settings = Settings()

# .env.example (Updated for Railway)
# Railway automatically provides these:
# DATABASE_URL - PostgreSQL connection string
# REDIS_URL - Redis connection string  
# PORT - Port to bind to
# RAILWAY_ENVIRONMENT - Current environment (production/staging)
# RAILWAY_STATIC_URL - Your app's URL

# You need to add these in Railway dashboard:
SECRET_KEY=your-secret-key-here-generate-with-openssl-rand-hex-32
STRIPE_SECRET_KEY=sk_test_your_stripe_key
STRIPE_WEBHOOK_SECRET=whsec_your_webhook_secret
OPENAI_API_KEY=sk-your-openai-key

# Optional overrides for local development:
DATABASE_URL=postgresql://postgres:password@localhost:5432/referralvillage
REDIS_URL=redis://localhost:6379
FRONTEND_URL=http://localhost:3000

# app/main.py (Updated with Railway optimizations)
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from app.core.config import settings
from app.api.api_v1.api import api_router
from app.db.init_db import init_db
import logging
import os

# Configure logging for Railway
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="ReferralVillage API",
    description="SaaS platform for creating and sharing referral-based leads",
    version="1.0.0",
    docs_url="/api/docs" if settings.RAILWAY_ENVIRONMENT != "production" else None,
    redoc_url="/api/redoc" if settings.RAILWAY_ENVIRONMENT != "production" else None,
)

# Trusted host middleware for Railway
if settings.RAILWAY_STATIC_URL:
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=[
            settings.RAILWAY_STATIC_URL,
            "*.railway.app",
            "localhost",
            "127.0.0.1"
        ]
    )

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.BACKEND_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(api_router, prefix=settings.API_V1_STR)

@app.on_event("startup")
async def startup_event():
    """Initialize database on startup"""
    logger.info(f"Starting ReferralVillage API in {settings.RAILWAY_ENVIRONMENT or 'local'} environment")
    logger.info(f"Database URL: {settings.DATABASE_URL.split('@')[1] if '@' in settings.DATABASE_URL else 'local'}")
    logger.info(f"Railway SHA: {settings.RAILWAY_GIT_COMMIT_SHA[:7] if settings.RAILWAY_GIT_COMMIT_SHA else 'local'}")
    
    # Initialize database
    init_db()

@app.get("/")
async def root():
    return {
        "message": "ReferralVillage API",
        "version": "1.0.0",
        "status": "Running",
        "environment": settings.RAILWAY_ENVIRONMENT or "local",
        "commit": settings.RAILWAY_GIT_COMMIT_SHA[:7] if settings.RAILWAY_GIT_COMMIT_SHA else None
    }

@app.get("/health")
async def health_check():
    """Health check endpoint for Railway"""
    return {
        "status": "healthy",
        "environment": settings.RAILWAY_ENVIRONMENT,
        "database": "connected" if check_database_connection() else "disconnected"
    }

def check_database_connection():
    """Check if database is accessible"""
    try:
        from app.db.session import engine
        with engine.connect() as conn:
            conn.execute("SELECT 1")
        return True
    except Exception as e:
        logger.error(f"Database connection failed: {e}")
        return False

# requirements.txt (Updated with production dependencies)
# Core
fastapi==0.110.0
uvicorn[standard]==0.27.0
gunicorn==21.2.0

# Database
sqlalchemy==2.0.25
alembic==1.13.1
psycopg2-binary==2.9.9

# Auth & Security
python-jose[cryptography]==3.3.0
passlib[bcrypt]==1.7.4
python-multipart==0.0.6
email-validator==2.1.0

# Integrations
stripe==7.12.0
openai==1.10.0
httpx==0.26.0

# Redis & Background Tasks
redis==5.0.1
celery==5.3.4

# Utils
pydantic==2.5.3
pydantic-settings==2.1.0
python-dotenv==1.0.0

# Monitoring (Railway friendly)
sentry-sdk[fastapi]==1.40.0

# Development
pytest==7.4.4
pytest-asyncio==0.23.3

# runtime.txt (Optional - specify Python version)
python-3.10.12

# .gitignore (Updated for Railway)
# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
venv/
env/
ENV/

# Environment
.env
.env.local
.env.*.local

# Database
*.db
*.sqlite3

# Logs
*.log

# IDE
.vscode/
.idea/
*.swp
*.swo

# Railway
.railway/

# Testing
.coverage
htmlcov/
.pytest_cache/

# OS
.DS_Store
Thumbs.db