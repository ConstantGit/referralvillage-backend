from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from app.core.config import settings
from app.api.api_v1.api import api_router
from app.db.init_db import init_db
from app.core.monitoring import init_sentry
from app.core.logging_middleware import LoggingMiddleware
import logging

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

# Initialize monitoring
init_sentry()

# Add middleware
app.add_middleware(LoggingMiddleware)

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

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.BACKEND_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router, prefix=settings.API_V1_STR)

@app.on_event("startup")
async def startup_event():
    logger.info(f"Starting ReferralVillage API in {settings.RAILWAY_ENVIRONMENT or 'local'} environment")
    init_db()

@app.get("/")
async def root():
    return {
        "message": "ReferralVillage API",
        "version": "1.0.0",
        "status": "Running",
        "environment": settings.RAILWAY_ENVIRONMENT or "local",
    }

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "environment": settings.RAILWAY_ENVIRONMENT,
    }
