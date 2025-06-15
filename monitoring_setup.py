# app/core/monitoring.py
import sentry_sdk
from sentry_sdk.integrations.fastapi import FastApiIntegration
from sentry_sdk.integrations.sqlalchemy import SqlalchemyIntegration
from sentry_sdk.integrations.redis import RedisIntegration
import logging
from app.core.config import settings
import time
from functools import wraps
from typing import Callable
import asyncio

# Configure structured logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
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
            send_default_pii=False,  # Don't send personally identifiable information
        )
        logger.info("Sentry initialized successfully")

# Custom metrics collector
class MetricsCollector:
    def __init__(self):
        self.metrics = {}
    
    def increment(self, metric: str, value: int = 1, tags: dict = None):
        """Increment a counter metric"""
        key = f"{metric}:{tags}" if tags else metric
        self.metrics[key] = self.metrics.get(key, 0) + value
    
    def gauge(self, metric: str, value: float, tags: dict = None):
        """Set a gauge metric"""
        key = f"{metric}:{tags}" if tags else metric
        self.metrics[key] = value
    
    def timing(self, metric: str):
        """Decorator for timing functions"""
        def decorator(func: Callable):
            @wraps(func)
            async def async_wrapper(*args, **kwargs):
                start_time = time.time()
                try:
                    result = await func(*args, **kwargs)
                    return result
                finally:
                    duration = (time.time() - start_time) * 1000  # ms
                    self.gauge(f"{metric}.duration", duration)
                    logger.info(f"{metric} took {duration:.2f}ms")
            
            @wraps(func)
            def sync_wrapper(*args, **kwargs):
                start_time = time.time()
                try:
                    result = func(*args, **kwargs)
                    return result
                finally:
                    duration = (time.time() - start_time) * 1000  # ms
                    self.gauge(f"{metric}.duration", duration)
                    logger.info(f"{metric} took {duration:.2f}ms")
            
            return async_wrapper if asyncio.iscoroutinefunction(func) else sync_wrapper
        return decorator

metrics = MetricsCollector()

# app/core/logging_middleware.py
from fastapi import Request
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
        
        # Log request
        logger.info(
            f"Request started",
            extra={
                "request_id": request_id,
                "method": request.method,
                "path": request.url.path,
                "client_host": request.client.host if request.client else None,
            }
        )
        
        # Time the request
        start_time = time.time()
        
        try:
            response = await call_next(request)
            duration = (time.time() - start_time) * 1000
            
            # Log response
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
            
            # Collect metrics
            metrics.increment("http.requests", tags={"status": response.status_code})
            metrics.gauge("http.request.duration", duration, tags={"endpoint": request.url.path})
            
            # Add request ID to response headers
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

# app/api/api_v1/endpoints/health.py
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.api import deps
from app.core.monitoring import metrics
import psutil
import redis
from app.core.config import settings

router = APIRouter()

@router.get("/health/detailed")
async def detailed_health_check(db: Session = Depends(deps.get_db)):
    """Detailed health check for monitoring"""
    health_status = {
        "status": "healthy",
        "checks": {}
    }
    
    # Database check
    try:
        db.execute("SELECT 1")
        health_status["checks"]["database"] = {
            "status": "healthy",
            "response_time_ms": 0
        }
    except Exception as e:
        health_status["status"] = "unhealthy"
        health_status["checks"]["database"] = {
            "status": "unhealthy",
            "error": str(e)
        }
    
    # Redis check
    try:
        r = redis.from_url(settings.REDIS_URL)
        r.ping()
        health_status["checks"]["redis"] = {
            "status": "healthy"
        }
    except Exception as e:
        health_status["checks"]["redis"] = {
            "status": "unhealthy",
            "error": str(e)
        }
    
    # System metrics
    health_status["metrics"] = {
        "cpu_percent": psutil.cpu_percent(),
        "memory_percent": psutil.virtual_memory().percent,
        "disk_percent": psutil.disk_usage('/').percent,
    }
    
    return health_status

# app/services/analytics_service.py
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from typing import Dict, List
import logging
from app.models import (
    User, Referral, Lead, Payout, SystemMetrics,
    ReferralStatus, LeadStatus, UserRole
)
from app.core.monitoring import metrics
from sqlalchemy import func, and_
from decimal import Decimal

logger = logging.getLogger(__name__)

class AnalyticsService:
    def __init__(self, db: Session):
        self.db = db
    
    @metrics.timing("analytics.calculate_mrr")
    def calculate_mrr(self) -> Decimal:
        """Calculate Monthly Recurring Revenue"""
        # This is a simplified version - adjust based on your pricing model
        thirty_days_ago = datetime.utcnow() - timedelta(days=30)
        
        completed_referrals = self.db.query(
            func.sum(Lead.deal_value * Referral.commission_value / 100)
        ).join(
            Referral, Lead.referral_id == Referral.id
        ).filter(
            and_(
                Lead.status == LeadStatus.WON,
                Lead.actual_close_date >= thirty_days_ago,
                Referral.commission_type == "percentage"
            )
        ).scalar() or Decimal(0)
        
        return completed_referrals
    
    def collect_daily_metrics(self):
        """Collect and store daily system metrics"""
        try:
            today = datetime.utcnow().date()
            
            # Check if metrics for today already exist
            existing = self.db.query(SystemMetrics).filter(
                func.date(SystemMetrics.metric_date) == today
            ).first()
            
            if existing:
                return
            
            # Calculate metrics
            total_users = self.db.query(func.count(User.id)).scalar()
            active_users = self.db.query(func.count(User.id)).filter(
                User.last_login >= datetime.utcnow() - timedelta(days=30)
            ).scalar()
            
            total_referrals = self.db.query(func.count(Referral.id)).scalar()
            completed_referrals = self.db.query(func.count(Referral.id)).filter(
                Referral.status == ReferralStatus.COMPLETED
            ).scalar()
            
            mrr = self.calculate_mrr()
            arr = mrr * 12
            
            # Store metrics
            metric = SystemMetrics(
                metric_date=datetime.utcnow(),
                total_users=total_users,
                active_users=active_users,
                total_referrals=total_referrals,
                completed_referrals=completed_referrals,
                total_revenue=Decimal(0),  # Calculate from payouts
                total_commissions_paid=Decimal(0),  # Calculate from payouts
                mrr=mrr,
                arr=arr
            )
            
            self.db.add(metric)
            self.db.commit()
            
            # Send metrics to monitoring
            metrics.gauge("business.mrr", float(mrr))
            metrics.gauge("business.active_users", active_users)
            metrics.gauge("business.conversion_rate", 
                         (completed_referrals / total_referrals * 100) if total_referrals > 0 else 0)
            
            logger.info(f"Daily metrics collected for {today}")
            
        except Exception as e:
            logger.error(f"Failed to collect daily metrics: {e}")
            self.db.rollback()

# Update app/core/config.py to include Sentry DSN
# Add this to the Settings class:
    # Monitoring
    SENTRY_DSN: Optional[str] = os.getenv("SENTRY_DSN", None)

# Update app/main.py to include monitoring
# Add these imports:
from app.core.monitoring import init_sentry
from app.core.logging_middleware import LoggingMiddleware

# Add after app creation:
# Initialize monitoring
init_sentry()

# Add middleware
app.add_middleware(LoggingMiddleware)

# Add to requirements.txt:
psutil==5.9.8