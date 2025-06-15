#!/usr/bin/env python3
"""
ReferralVillage Backend Setup Completion Script
This creates all the Python source files for the FastAPI backend
"""

import os
import sys

def create_file(path, content):
    """Create a file with the given content"""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w') as f:
        f.write(content)
    print(f"✅ Created: {path}")

def main():
    print("🚀 ReferralVillage Python Setup - Part 2")
    print("======================================")
    print("Creating all Python source files...\n")

    # Check if we're in the right directory
    if not os.path.exists("app"):
        print("❌ Error: 'app' directory not found. Run this from your repository root.")
        print("   Make sure you've run the migration script first!")
        sys.exit(1)

    # Core Config
    create_file("app/core/config.py", '''from typing import List, Union, Optional
from pydantic_settings import BaseSettings
from pydantic import AnyHttpUrl, validator
import os

class Settings(BaseSettings):
    API_V1_STR: str = "/api/v1"
    PROJECT_NAME: str = "ReferralVillage"
    
    PORT: int = int(os.getenv("PORT", 8000))
    
    SECRET_KEY: str = os.getenv("SECRET_KEY", "your-secret-key-change-in-production")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 8
    
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL",
        "postgresql://postgres:password@localhost:5432/referralvillage"
    )
    
    @validator("DATABASE_URL", pre=True)
    def validate_postgres_url(cls, v: str) -> str:
        if v.startswith("postgres://"):
            return v.replace("postgres://", "postgresql://", 1)
        return v
    
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379")
    
    RAILWAY_ENVIRONMENT: Optional[str] = os.getenv("RAILWAY_ENVIRONMENT")
    RAILWAY_STATIC_URL: Optional[str] = os.getenv("RAILWAY_STATIC_URL")
    RAILWAY_GIT_COMMIT_SHA: Optional[str] = os.getenv("RAILWAY_GIT_COMMIT_SHA")
    
    BACKEND_CORS_ORIGINS: List[AnyHttpUrl] = []
    
    @validator("BACKEND_CORS_ORIGINS", pre=True)
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> Union[List[str], str]:
        if isinstance(v, str) and not v.startswith("["):
            return [i.strip() for i in v.split(",")]
        elif isinstance(v, (list, str)):
            return v
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
    
    STRIPE_SECRET_KEY: str = os.getenv("STRIPE_SECRET_KEY", "")
    STRIPE_WEBHOOK_SECRET: str = os.getenv("STRIPE_WEBHOOK_SECRET", "")
    
    OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")
    
    SENTRY_DSN: Optional[str] = os.getenv("SENTRY_DSN", None)
    
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
''')

    # Core Security
    create_file("app/core/security.py", '''from datetime import datetime, timedelta
from typing import Any, Union
from jose import jwt
from passlib.context import CryptContext
from app.core.config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def create_access_token(
    subject: Union[str, Any], expires_delta: timedelta = None
) -> str:
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(
            minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
        )
    to_encode = {"exp": expire, "sub": str(subject)}
    encoded_jwt = jwt.encode(
        to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM
    )
    return encoded_jwt

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)
''')

    # Core Monitoring
    create_file("app/core/monitoring.py", '''import sentry_sdk
from sentry_sdk.integrations.fastapi import FastApiIntegration
from sentry_sdk.integrations.sqlalchemy import SqlalchemyIntegration
from sentry_sdk.integrations.redis import RedisIntegration
import logging
from app.core.config import settings
import time
from functools import wraps
from typing import Callable
import asyncio

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)

logger = logging.getLogger(__name__)

def init_sentry():
    """Initialize Sentry error tracking"""
    if settings.SENTRY_DSN:
        sentry_sdk.init(
            dsn=settings.SENTRY_DSN,
            integrations=[
                FastApiIntegration(transaction_style="endpoint"),
                SqlalchemyIntegration(),
                RedisIntegration(),
            ],
            traces_sample_rate=0.1 if settings.RAILWAY_ENVIRONMENT == "production" else 1.0,
            environment=settings.RAILWAY_ENVIRONMENT or "local",
            release=settings.RAILWAY_GIT_COMMIT_SHA,
            attach_stacktrace=True,
            send_default_pii=False,
        )
        logger.info("Sentry initialized successfully")

class MetricsCollector:
    def __init__(self):
        self.metrics = {}
    
    def increment(self, metric: str, value: int = 1, tags: dict = None):
        key = f"{metric}:{tags}" if tags else metric
        self.metrics[key] = self.metrics.get(key, 0) + value
    
    def gauge(self, metric: str, value: float, tags: dict = None):
        key = f"{metric}:{tags}" if tags else metric
        self.metrics[key] = value
    
    def timing(self, metric: str):
        def decorator(func: Callable):
            @wraps(func)
            async def async_wrapper(*args, **kwargs):
                start_time = time.time()
                try:
                    result = await func(*args, **kwargs)
                    return result
                finally:
                    duration = (time.time() - start_time) * 1000
                    self.gauge(f"{metric}.duration", duration)
                    logger.info(f"{metric} took {duration:.2f}ms")
            
            @wraps(func)
            def sync_wrapper(*args, **kwargs):
                start_time = time.time()
                try:
                    result = func(*args, **kwargs)
                    return result
                finally:
                    duration = (time.time() - start_time) * 1000
                    self.gauge(f"{metric}.duration", duration)
                    logger.info(f"{metric} took {duration:.2f}ms")
            
            return async_wrapper if asyncio.iscoroutinefunction(func) else sync_wrapper
        return decorator

metrics = MetricsCollector()
''')

    # Logging Middleware
    create_file("app/core/logging_middleware.py", '''from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response
import time
import uuid
import logging
from app.core.monitoring import metrics

logger = logging.getLogger(__name__)

class LoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        request_id = str(uuid.uuid4())
        request.state.request_id = request_id
        
        logger.info(
            f"Request started",
            extra={
                "request_id": request_id,
                "method": request.method,
                "path": request.url.path,
                "client_host": request.client.host if request.client else None,
            }
        )
        
        start_time = time.time()
        
        try:
            response = await call_next(request)
            duration = (time.time() - start_time) * 1000
            
            logger.info(
                f"Request completed",
                extra={
                    "request_id": request_id,
                    "method": request.method,
                    "path": request.url.path,
                    "status_code": response.status_code,
                    "duration_ms": duration,
                }
            )
            
            metrics.increment("http.requests", tags={"status": response.status_code})
            metrics.gauge("http.request.duration", duration, tags={"endpoint": request.url.path})
            
            response.headers["X-Request-ID"] = request_id
            
            return response
            
        except Exception as e:
            duration = (time.time() - start_time) * 1000
            logger.error(
                f"Request failed",
                extra={
                    "request_id": request_id,
                    "method": request.method,
                    "path": request.url.path,
                    "duration_ms": duration,
                    "error": str(e),
                },
                exc_info=True
            )
            metrics.increment("http.requests", tags={"status": 500})
            raise
''')

    # Models
    create_file("app/models/__init__.py", '''from app.models.models import *
''')

    create_file("app/models/models.py", '''from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, Text, ForeignKey, Enum, JSON, DECIMAL
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.sql import func
from datetime import datetime
import enum

Base = declarative_base()

class UserRole(enum.Enum):
    AGENT = "agent"
    VENDOR = "vendor"
    ADMIN = "admin"

class ReferralStatus(enum.Enum):
    DRAFT = "draft"
    ACTIVE = "active"
    MATCHED = "matched"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    EXPIRED = "expired"

class LeadStatus(enum.Enum):
    NEW = "new"
    CONTACTED = "contacted"
    QUALIFIED = "qualified"
    PROPOSAL_SENT = "proposal_sent"
    NEGOTIATING = "negotiating"
    WON = "won"
    LOST = "lost"

class PayoutStatus(enum.Enum):
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    REFUNDED = "refunded"

class VerificationStatus(enum.Enum):
    PENDING = "pending"
    IN_REVIEW = "in_review"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"

class NotificationType(enum.Enum):
    REFERRAL_MATCH = "referral_match"
    LEAD_UPDATE = "lead_update"
    PAYOUT_PROCESSED = "payout_processed"
    VERIFICATION_UPDATE = "verification_update"
    SYSTEM_ALERT = "system_alert"

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(Enum(UserRole), default=UserRole.AGENT, nullable=False)
    
    first_name = Column(String(100), nullable=False)
    last_name = Column(String(100), nullable=False)
    company_name = Column(String(255))
    phone = Column(String(20))
    avatar_url = Column(String(500))
    bio = Column(Text)
    
    stripe_customer_id = Column(String(255), unique=True)
    stripe_account_id = Column(String(255), unique=True)
    
    notification_preferences = Column(JSON, default=lambda: {
        "email": True,
        "sms": False,
        "in_app": True
    })
    
    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)
    last_login = Column(DateTime)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    
    referrals_created = relationship("Referral", back_populates="creator", foreign_keys="Referral.creator_id")
    referrals_assigned = relationship("Referral", back_populates="assigned_vendor", foreign_keys="Referral.assigned_vendor_id")
    leads = relationship("Lead", back_populates="vendor")
    verifications = relationship("ContractorVerification", back_populates="user")
    payouts = relationship("Payout", back_populates="user")
    notifications = relationship("Notification", back_populates="user")
    analytics_events = relationship("AnalyticsEvent", back_populates="user")

class Category(Base):
    __tablename__ = "categories"
    
    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False, unique=True)
    slug = Column(String(100), nullable=False, unique=True, index=True)
    description = Column(Text)
    icon = Column(String(50))
    parent_id = Column(Integer, ForeignKey("categories.id"))
    
    meta_title = Column(String(255))
    meta_description = Column(Text)
    is_featured = Column(Boolean, default=False)
    display_order = Column(Integer, default=0)
    
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    
    parent = relationship("Category", remote_side=[id])
    referrals = relationship("Referral", back_populates="category")

class Referral(Base):
    __tablename__ = "referrals"
    
    id = Column(Integer, primary_key=True)
    creator_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    assigned_vendor_id = Column(Integer, ForeignKey("users.id"))
    category_id = Column(Integer, ForeignKey("categories.id"), nullable=False)
    
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    budget_min = Column(DECIMAL(10, 2))
    budget_max = Column(DECIMAL(10, 2))
    commission_type = Column(String(50), default="percentage")
    commission_value = Column(DECIMAL(10, 2), nullable=False)
    
    client_name = Column(String(255), nullable=False)
    client_email = Column(String(255), nullable=False)
    client_phone = Column(String(20))
    client_company = Column(String(255))
    
    location = Column(String(255))
    preferred_contact_method = Column(String(50), default="email")
    urgency = Column(String(50), default="normal")
    
    ai_match_score = Column(Float)
    ai_match_reasons = Column(JSON)
    matching_criteria = Column(JSON)
    
    status = Column(Enum(ReferralStatus), default=ReferralStatus.DRAFT)
    expires_at = Column(DateTime)
    matched_at = Column(DateTime)
    completed_at = Column(DateTime)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    
    creator = relationship("User", back_populates="referrals_created", foreign_keys=[creator_id])
    assigned_vendor = relationship("User", back_populates="referrals_assigned", foreign_keys=[assigned_vendor_id])
    category = relationship("Category", back_populates="referrals")
    leads = relationship("Lead", back_populates="referral")
    commission_payouts = relationship("CommissionPayout", back_populates="referral")

class Lead(Base):
    __tablename__ = "leads"
    
    id = Column(Integer, primary_key=True)
    referral_id = Column(Integer, ForeignKey("referrals.id"), nullable=False)
    vendor_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    
    status = Column(Enum(LeadStatus), default=LeadStatus.NEW)
    notes = Column(Text)
    next_action = Column(String(255))
    next_action_date = Column(DateTime)
    
    deal_value = Column(DECIMAL(10, 2))
    probability = Column(Integer)
    expected_close_date = Column(DateTime)
    actual_close_date = Column(DateTime)
    
    last_contact_date = Column(DateTime)
    contact_count = Column(Integer, default=0)
    
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    
    referral = relationship("Referral", back_populates="leads")
    vendor = relationship("User", back_populates="leads")
    activities = relationship("LeadActivity", back_populates="lead")

class LeadActivity(Base):
    __tablename__ = "lead_activities"
    
    id = Column(Integer, primary_key=True)
    lead_id = Column(Integer, ForeignKey("leads.id"), nullable=False)
    
    activity_type = Column(String(50), nullable=False)
    description = Column(Text)
    outcome = Column(String(255))
    
    created_at = Column(DateTime, default=func.now())
    
    lead = relationship("Lead", back_populates="activities")

class ContractorVerification(Base):
    __tablename__ = "contractor_verifications"
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    
    verification_type = Column(String(50), nullable=False)
    document_url = Column(String(500))
    document_number = Column(String(255))
    issuing_authority = Column(String(255))
    
    status = Column(Enum(VerificationStatus), default=VerificationStatus.PENDING)
    verified_by = Column(Integer, ForeignKey("users.id"))
    rejection_reason = Column(Text)
    
    issue_date = Column(DateTime)
    expiry_date = Column(DateTime)
    verified_at = Column(DateTime)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    
    user = relationship("User", back_populates="verifications", foreign_keys=[user_id])

class CommissionPayout(Base):
    __tablename__ = "commission_payouts"
    
    id = Column(Integer, primary_key=True)
    referral_id = Column(Integer, ForeignKey("referrals.id"), nullable=False)
    payout_id = Column(Integer, ForeignKey("payouts.id"))
    
    commission_amount = Column(DECIMAL(10, 2), nullable=False)
    deal_value = Column(DECIMAL(10, 2), nullable=False)
    
    is_paid = Column(Boolean, default=False)
    paid_at = Column(DateTime)
    
    created_at = Column(DateTime, default=func.now())
    
    referral = relationship("Referral", back_populates="commission_payouts")
    payout = relationship("Payout", back_populates="commissions")

class Payout(Base):
    __tablename__ = "payouts"
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    
    amount = Column(DECIMAL(10, 2), nullable=False)
    currency = Column(String(3), default="USD")
    status = Column(Enum(PayoutStatus), default=PayoutStatus.PENDING)
    
    stripe_payout_id = Column(String(255), unique=True)
    stripe_transfer_id = Column(String(255), unique=True)
    
    processed_at = Column(DateTime)
    failed_reason = Column(Text)
    
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    
    user = relationship("User", back_populates="payouts")
    commissions = relationship("CommissionPayout", back_populates="payout")

class Notification(Base):
    __tablename__ = "notifications"
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    
    type = Column(Enum(NotificationType), nullable=False)
    title = Column(String(255), nullable=False)
    message = Column(Text, nullable=False)
    data = Column(JSON)
    
    is_read = Column(Boolean, default=False)
    read_at = Column(DateTime)
    
    created_at = Column(DateTime, default=func.now())
    
    user = relationship("User", back_populates="notifications")

class AnalyticsEvent(Base):
    __tablename__ = "analytics_events"
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    
    event_type = Column(String(100), nullable=False, index=True)
    event_category = Column(String(100))
    event_data = Column(JSON)
    
    ip_address = Column(String(45))
    user_agent = Column(String(500))
    session_id = Column(String(255))
    
    created_at = Column(DateTime, default=func.now(), index=True)
    
    user = relationship("User", back_populates="analytics_events")

class SystemMetrics(Base):
    __tablename__ = "system_metrics"
    
    id = Column(Integer, primary_key=True)
    
    metric_date = Column(DateTime, nullable=False, unique=True, index=True)
    total_users = Column(Integer, default=0)
    active_users = Column(Integer, default=0)
    total_referrals = Column(Integer, default=0)
    completed_referrals = Column(Integer, default=0)
    total_revenue = Column(DECIMAL(10, 2), default=0)
    total_commissions_paid = Column(DECIMAL(10, 2), default=0)
    
    mrr = Column(DECIMAL(10, 2), default=0)
    arr = Column(DECIMAL(10, 2), default=0)
    
    created_at = Column(DateTime, default=func.now())
''')

    # Database files
    create_file("app/db/base_class.py", '''from typing import Any
from sqlalchemy.ext.declarative import as_declarative, declared_attr

@as_declarative()
class Base:
    id: Any
    __name__: str
    
    @declared_attr
    def __tablename__(cls) -> str:
        return cls.__name__.lower()
''')

    create_file("app/db/base.py", '''from app.db.base_class import Base
from app.models import (
    User, Category, Referral, Lead, LeadActivity,
    ContractorVerification, CommissionPayout, Payout,
    Notification, AnalyticsEvent, SystemMetrics
)
''')

    create_file("app/db/session.py", '''from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.core.config import settings

engine = create_engine(settings.DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
''')

    create_file("app/db/init_db.py", '''from sqlalchemy.orm import Session
from app.db import base
from app.db.session import engine

def init_db() -> None:
    base.Base.metadata.create_all(bind=engine)
''')

    # API Dependencies
    create_file("app/api/deps.py", '''from typing import Generator
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from pydantic import ValidationError
from sqlalchemy.orm import Session
from datetime import datetime

from app.core import security
from app.core.config import settings
from app.db.session import SessionLocal
from app.models import User
from app.schemas.token import TokenPayload

oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"{settings.API_V1_STR}/auth/login")

def get_db() -> Generator:
    try:
        db = SessionLocal()
        yield db
    finally:
        db.close()

def get_current_user(
    db: Session = Depends(get_db),
    token: str = Depends(oauth2_scheme)
) -> User:
    try:
        payload = jwt.decode(
            token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
        )
        token_data = TokenPayload(**payload)
    except (JWTError, ValidationError):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Could not validate credentials",
        )
    user = db.query(User).filter(User.id == token_data.sub).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

def get_current_active_user(
    current_user: User = Depends(get_current_user),
) -> User:
    if not current_user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user
''')

    # API Router
    create_file("app/api/api_v1/api.py", '''from fastapi import APIRouter
from app.api.api_v1.endpoints import auth, users, referrals, leads, categories

api_router = APIRouter()

api_router.include_router(auth.router, prefix="/auth", tags=["authentication"])
api_router.include_router(users.router, prefix="/users", tags=["users"])
api_router.include_router(referrals.router, prefix="/referrals", tags=["referrals"])
api_router.include_router(leads.router, prefix="/leads", tags=["leads"])
api_router.include_router(categories.router, prefix="/categories", tags=["categories"])
''')

    # Basic Auth Endpoint
    create_file("app/api/api_v1/endpoints/auth.py", '''from datetime import timedelta
from typing import Any
from fastapi import APIRouter, Body, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from datetime import datetime

from app import models
from app.api import deps
from app.core import security
from app.core.config import settings
from app.core.security import get_password_hash, verify_password
from app.schemas import user as user_schemas
from app.schemas.token import Token

router = APIRouter()

@router.post("/register", response_model=user_schemas.User)
def register(
    *,
    db: Session = Depends(deps.get_db),
    user_in: user_schemas.UserCreate,
) -> Any:
    """Register new user"""
    user = db.query(models.User).filter(models.User.email == user_in.email).first()
    if user:
        raise HTTPException(
            status_code=400,
            detail="User with this email already exists"
        )
    
    user = models.User(
        email=user_in.email,
        password_hash=get_password_hash(user_in.password),
        first_name=user_in.first_name,
        last_name=user_in.last_name,
        role=user_in.role,
        company_name=user_in.company_name,
        phone=user_in.phone,
        bio=user_in.bio,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    
    return user

@router.post("/login", response_model=Token)
def login(
    db: Session = Depends(deps.get_db),
    form_data: OAuth2PasswordRequestForm = Depends()
) -> Any:
    """OAuth2 compatible token login"""
    user = db.query(models.User).filter(
        models.User.email == form_data.username
    ).first()
    
    if not user or not verify_password(form_data.password, user.password_hash):
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    elif not user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = security.create_access_token(
        user.id, expires_delta=access_token_expires
    )
    
    user.last_login = datetime.utcnow()
    db.commit()
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
    }

@router.get("/me", response_model=user_schemas.User)
def read_users_me(
    current_user: models.User = Depends(deps.get_current_active_user),
) -> Any:
    """Get current user"""
    return current_user
''')

    # Other basic endpoints
    create_file("app/api/api_v1/endpoints/users.py", '''from typing import Any, List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app import models
from app.api import deps
from app.schemas import user as user_schemas

router = APIRouter()

@router.get("/", response_model=List[user_schemas.User])
def read_users(
    db: Session = Depends(deps.get_db),
    skip: int = 0,
    limit: int = 100,
    current_user: models.User = Depends(deps.get_current_active_user),
) -> Any:
    """Retrieve users"""
    if current_user.role != models.UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Not enough permissions")
    
    users = db.query(models.User).offset(skip).limit(limit).all()
    return users

@router.get("/{user_id}", response_model=user_schemas.User)
def read_user(
    user_id: int,
    current_user: models.User = Depends(deps.get_current_active_user),
    db: Session = Depends(deps.get_db),
) -> Any:
    """Get user by ID"""
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if current_user.id != user_id and current_user.role != models.UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Not enough permissions")
    
    return user
''')

    create_file("app/api/api_v1/endpoints/referrals.py", '''from typing import Any, List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app import models
from app.api import deps

router = APIRouter()

@router.get("/")
def read_referrals(
    db: Session = Depends(deps.get_db),
    skip: int = 0,
    limit: int = 100,
    current_user: models.User = Depends(deps.get_current_active_user),
) -> Any:
    """Get referrals"""
    query = db.query(models.Referral)
    
    if current_user.role == models.UserRole.AGENT:
        query = query.filter(models.Referral.creator_id == current_user.id)
    elif current_user.role == models.UserRole.VENDOR:
        query = query.filter(
            (models.Referral.assigned_vendor_id == current_user.id) |
            (models.Referral.status == models.ReferralStatus.ACTIVE)
        )
    
    referrals = query.offset(skip).limit(limit).all()
    return referrals
''')

    create_file("app/api/api_v1/endpoints/leads.py", '''from typing import Any, List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app import models
from app.api import deps

router = APIRouter()

@router.get("/")
def read_leads(
    db: Session = Depends(deps.get_db),
    skip: int = 0,
    limit: int = 100,
    current_user: models.User = Depends(deps.get_current_active_user),
) -> Any:
    """Get leads for current vendor"""
    if current_user.role != models.UserRole.VENDOR:
        raise HTTPException(status_code=403, detail="Only vendors can view leads")
    
    leads = db.query(models.Lead).filter(
        models.Lead.vendor_id == current_user.id
    ).offset(skip).limit(limit).all()
    
    return leads
''')

    create_file("app/api/api_v1/endpoints/categories.py", '''from typing import Any, List
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app import models
from app.api import deps

router = APIRouter()

@router.get("/")
def read_categories(
    db: Session = Depends(deps.get_db),
    skip: int = 0,
    limit: int = 100,
) -> Any:
    """Get all active categories"""
    categories = db.query(models.Category).filter(
        models.Category.is_active == True
    ).offset(skip).limit(limit).all()
    return categories
''')

    # Basic Schemas
    create_file("app/schemas/__init__.py", '''from app.schemas.user import User, UserCreate, UserUpdate
from app.schemas.token import Token, TokenPayload
''')

    create_file("app/schemas/token.py", '''from typing import Optional
from pydantic import BaseModel

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenPayload(BaseModel):
    sub: Optional[int] = None
''')

    create_file("app/schemas/user.py", '''from typing import Optional, Dict
from pydantic import BaseModel, EmailStr
from datetime import datetime
from app.models import UserRole

class UserBase(BaseModel):
    email: EmailStr
    first_name: str
    last_name: str
    role: UserRole = UserRole.AGENT
    company_name: Optional[str] = None
    phone: Optional[str] = None
    bio: Optional[str] = None

class UserCreate(UserBase):
    password: str

class UserUpdate(UserBase):
    password: Optional[str] = None

class UserInDBBase(UserBase):
    id: int
    is_active: bool
    is_verified: bool
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True

class User(UserInDBBase):
    pass
''')

    # Services placeholder
    create_file("app/services/ai_matching_service.py", '''from sqlalchemy.orm import Session
from app.models import Referral, User
from typing import List, Dict
import logging

logger = logging.getLogger(__name__)

class AIMatchingService:
    def __init__(self, db: Session):
        self.db = db
    
    async def find_matches(self, referral: Referral) -> List[Dict]:
        """Find matching vendors for a referral using AI"""
        # TODO: Implement actual AI matching logic
        # For now, return mock data
        vendors = self.db.query(User).filter(
            User.role == "vendor",
            User.is_active == True
        ).limit(5).all()
        
        matches = []
        for vendor in vendors:
            matches.append({
                "vendor_id": vendor.id,
                "vendor_name": f"{vendor.first_name} {vendor.last_name}",
                "score": 85.0,
                "reasons": ["High rating", "Experience in category"]
            })
        
        return matches
''')

    # Alembic files
    create_file("alembic/env.py", '''from logging.config import fileConfig
from sqlalchemy import engine_from_config
from sqlalchemy import pool
from alembic import context
import os
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).parent.parent))

from app.db.base import Base
from app.core.config import settings

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata

def get_url():
    return os.getenv("DATABASE_URL", settings.DATABASE_URL)

def run_migrations_offline() -> None:
    url = get_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()

def run_migrations_online() -> None:
    configuration = config.get_section(config.config_ini_section)
    configuration["sqlalchemy.url"] = get_url()
    
    connectable = engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection, target_metadata=target_metadata
        )

        with context.begin_transaction():
            context.run_migrations()

if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
''')

    create_file("alembic/script.py.mako", '''"""${message}

Revision ID: ${up_revision}
Revises: ${down_revision | comma,n}
Create Date: ${create_date}

"""
from alembic import op
import sqlalchemy as sa
${imports if imports else ""}

# revision identifiers, used by Alembic.
revision = ${repr(up_revision)}
down_revision = ${repr(down_revision)}
branch_labels = ${repr(branch_labels)}
depends_on = ${repr(depends_on)}


def upgrade() -> None:
    ${upgrades if upgrades else "pass"}


def downgrade() -> None:
    ${downgrades if downgrades else "pass"}
''')

    # Scripts
    create_file("scripts/init_db.py", '''"""Initialize database with sample data"""
from sqlalchemy.orm import Session
from app.db.session import SessionLocal, engine
from app.db.base import Base
from app.models import User, Category, UserRole
from app.core.security import get_password_hash
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def init_db(db: Session) -> None:
    """Initialize database with base data"""
    
    Base.metadata.create_all(bind=engine)
    logger.info("Database tables created")
    
    if db.query(User).first():
        logger.info("Database already initialized")
        return
    
    admin = User(
        email="admin@referralvillage.com",
        password_hash=get_password_hash("admin123"),
        first_name="Admin",
        last_name="User",
        role=UserRole.ADMIN,
        is_verified=True,
        is_active=True
    )
    db.add(admin)
    
    categories = [
        {"name": "Home Services", "slug": "home-services", "icon": "🏠"},
        {"name": "Professional Services", "slug": "professional-services", "icon": "💼"},
        {"name": "Technology", "slug": "technology", "icon": "💻"},
        {"name": "Marketing", "slug": "marketing", "icon": "📱"},
        {"name": "Finance", "slug": "finance", "icon": "💰"},
        {"name": "Real Estate", "slug": "real-estate", "icon": "🏢"},
        {"name": "Healthcare", "slug": "healthcare", "icon": "🏥"},
        {"name": "Education", "slug": "education", "icon": "🎓"},
    ]
    
    for cat_data in categories:
        category = Category(**cat_data, is_active=True)
        db.add(category)
    
    db.commit()
    logger.info("Database initialized with sample data")

if __name__ == "__main__":
    db = SessionLocal()
    try:
        init_db(db)
    finally:
        db.close()
''')

    # Tests
    create_file("tests/conftest.py", '''import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.main import app
from app.api.deps import get_db
from app.db.base import Base

SQLALCHEMY_DATABASE_URL = "sqlite:///./test.db"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base.metadata.create_all(bind=engine)

def override_get_db():
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()

app.dependency_overrides[get_db] = override_get_db

@pytest.fixture
def client():
    return TestClient(app)

@pytest.fixture
def db():
    return TestingSessionLocal()
''')

    create_file("tests/test_main.py", '''def test_read_main(client):
    response = client.get("/")
    assert response.status_code == 200
    assert response.json()["message"] == "ReferralVillage API"

def test_health_check(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"
''')

    print("\n✅ All Python files created successfully!")
    print("\n📋 Final steps:")
    print("1. Commit all changes: git add -A && git commit -m 'Complete Python/FastAPI migration'")
    print("2. Push to GitHub: git push origin main")
    print("3. Add RAILWAY_TOKEN to GitHub Secrets")
    print("4. Add environment variables in Railway dashboard:")
    print("   - SECRET_KEY (generate with: openssl rand -hex 32)")
    print("   - STRIPE_SECRET_KEY")
    print("   - OPENAI_API_KEY")
    print("\n🎉 Your ReferralVillage backend is ready for deployment!")

if __name__ == "__main__":
    main()
''')

    print("\n✅ Second script created successfully!")
    print("\n🚀 To complete the setup:")
    print("1. Run: python3 complete_setup.py")
    print("2. This will create all remaining Python files")
    print("3. Then commit and push to GitHub")

# Make the script executable
try:
    os.chmod("complete_setup.py", 0o755)
except:
    pass

if __name__ == "__main__":
    main()
