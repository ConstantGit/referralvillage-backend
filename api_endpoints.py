# app/api/api_v1/api.py
from fastapi import APIRouter
from app.api.api_v1.endpoints import (
    auth, users, referrals, leads, categories, analytics, health
)

api_router = APIRouter()

api_router.include_router(auth.router, prefix="/auth", tags=["authentication"])
api_router.include_router(users.router, prefix="/users", tags=["users"])
api_router.include_router(referrals.router, prefix="/referrals", tags=["referrals"])
api_router.include_router(leads.router, prefix="/leads", tags=["leads"])
api_router.include_router(categories.router, prefix="/categories", tags=["categories"])
api_router.include_router(analytics.router, prefix="/analytics", tags=["analytics"])
api_router.include_router(health.router, prefix="/health", tags=["health"])

# app/api/api_v1/endpoints/auth.py
from datetime import timedelta
from typing import Any
from fastapi import APIRouter, Body, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from app import models, schemas
from app.api import deps
from app.core import security
from app.core.config import settings
from app.core.security import get_password_hash, verify_password
from app.core.monitoring import metrics

router = APIRouter()

@router.post("/register", response_model=schemas.User)
def register(
    *,
    db: Session = Depends(deps.get_db),
    user_in: schemas.UserCreate,
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
    
    metrics.increment("users.registered", tags={"role": user.role.value})
    return user

@router.post("/login", response_model=schemas.Token)
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
    
    # Update last login
    user.last_login = datetime.utcnow()
    db.commit()
    
    metrics.increment("auth.login", tags={"role": user.role.value})
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
    }

@router.get("/me", response_model=schemas.User)
def read_users_me(
    current_user: models.User = Depends(deps.get_current_active_user),
) -> Any:
    """Get current user"""
    return current_user

# app/api/api_v1/endpoints/users.py
from typing import Any, List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app import models, schemas
from app.api import deps
from app.core.monitoring import metrics

router = APIRouter()

@router.get("/", response_model=List[schemas.User])
def read_users(
    db: Session = Depends(deps.get_db),
    skip: int = 0,
    limit: int = 100,
    current_user: models.User = Depends(deps.get_current_active_user),
) -> Any:
    """Retrieve users (admin only)"""
    if current_user.role != models.UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Not enough permissions")
    
    users = db.query(models.User).offset(skip).limit(limit).all()
    return users

@router.get("/{user_id}", response_model=schemas.User)
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

@router.put("/{user_id}", response_model=schemas.User)
def update_user(
    *,
    db: Session = Depends(deps.get_db),
    user_id: int,
    user_in: schemas.UserUpdate,
    current_user: models.User = Depends(deps.get_current_active_user),
) -> Any:
    """Update user"""
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if current_user.id != user_id and current_user.role != models.UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Not enough permissions")
    
    update_data = user_in.dict(exclude_unset=True)
    if "password" in update_data:
        update_data["password_hash"] = get_password_hash(update_data.pop("password"))
    
    for field, value in update_data.items():
        setattr(user, field, value)
    
    db.commit()
    db.refresh(user)
    return user

# app/api/api_v1/endpoints/referrals.py
from typing import Any, List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from datetime import datetime

from app import models, schemas
from app.api import deps
from app.services.ai_matching_service import AIMatchingService
from app.core.monitoring import metrics

router = APIRouter()

@router.get("/", response_model=List[schemas.Referral])
def read_referrals(
    db: Session = Depends(deps.get_db),
    skip: int = 0,
    limit: int = 100,
    status: str = None,
    current_user: models.User = Depends(deps.get_current_active_user),
) -> Any:
    """Get referrals based on user role"""
    query = db.query(models.Referral)
    
    if current_user.role == models.UserRole.AGENT:
        # Agents see only their created referrals
        query = query.filter(models.Referral.creator_id == current_user.id)
    elif current_user.role == models.UserRole.VENDOR:
        # Vendors see referrals assigned to them or available for matching
        query = query.filter(
            (models.Referral.assigned_vendor_id == current_user.id) |
            (models.Referral.status == models.ReferralStatus.ACTIVE)
        )
    
    if status:
        query = query.filter(models.Referral.status == status)
    
    referrals = query.offset(skip).limit(limit).all()
    return referrals

@router.post("/", response_model=schemas.Referral)
async def create_referral(
    *,
    db: Session = Depends(deps.get_db),
    referral_in: schemas.ReferralCreate,
    current_user: models.User = Depends(deps.get_current_active_user),
) -> Any:
    """Create new referral (agents only)"""
    if current_user.role != models.UserRole.AGENT:
        raise HTTPException(
            status_code=403,
            detail="Only agents can create referrals"
        )
    
    referral = models.Referral(
        **referral_in.dict(),
        creator_id=current_user.id,
        status=models.ReferralStatus.DRAFT
    )
    db.add(referral)
    db.commit()
    db.refresh(referral)
    
    metrics.increment("referrals.created", tags={"category": referral.category_id})
    return referral

@router.post("/{referral_id}/publish", response_model=schemas.ReferralWithMatches)
async def publish_referral(
    *,
    db: Session = Depends(deps.get_db),
    referral_id: int,
    current_user: models.User = Depends(deps.get_current_active_user),
) -> Any:
    """Publish referral and find AI matches"""
    referral = db.query(models.Referral).filter(
        models.Referral.id == referral_id
    ).first()
    
    if not referral:
        raise HTTPException(status_code=404, detail="Referral not found")
    
    if referral.creator_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    if referral.status != models.ReferralStatus.DRAFT:
        raise HTTPException(status_code=400, detail="Referral already published")
    
    # Update status
    referral.status = models.ReferralStatus.ACTIVE
    
    # Run AI matching
    matching_service = AIMatchingService(db)
    matches = await matching_service.find_matches(referral)
    
    # Store AI match results
    if matches:
        referral.ai_match_score = matches[0]["score"]
        referral.ai_match_reasons = {"matches": matches[:5]}  # Top 5 matches
    
    db.commit()
    db.refresh(referral)
    
    return {
        **referral.__dict__,
        "potential_vendors": matches[:5]
    }

@router.post("/{referral_id}/assign/{vendor_id}")
def assign_referral(
    *,
    db: Session = Depends(deps.get_db),
    referral_id: int,
    vendor_id: int,
    current_user: models.User = Depends(deps.get_current_active_user),
) -> Any:
    """Assign referral to vendor"""
    referral = db.query(models.Referral).filter(
        models.Referral.id == referral_id
    ).first()
    
    if not referral:
        raise HTTPException(status_code=404, detail="Referral not found")
    
    if referral.creator_id != current_user.id and current_user.role != models.UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    vendor = db.query(models.User).filter(
        models.User.id == vendor_id,
        models.User.role == models.UserRole.VENDOR
    ).first()
    
    if not vendor:
        raise HTTPException(status_code=404, detail="Vendor not found")
    
    referral.assigned_vendor_id = vendor_id
    referral.status = models.ReferralStatus.MATCHED
    referral.matched_at = datetime.utcnow()
    
    # Create initial lead
    lead = models.Lead(
        referral_id=referral_id,
        vendor_id=vendor_id,
        status=models.LeadStatus.NEW
    )
    db.add(lead)
    
    db.commit()
    
    metrics.increment("referrals.assigned", tags={"category": referral.category_id})
    return {"message": "Referral assigned successfully"}

# app/api/api_v1/endpoints/categories.py
from typing import Any, List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app import models, schemas
from app.api import deps

router = APIRouter()

@router.get("/", response_model=List[schemas.Category])
def read_categories(
    db: Session = Depends(deps.get_db),
    skip: int = 0,
    limit: int = 100,
    featured_only: bool = False,
) -> Any:
    """Get all active categories"""
    query = db.query(models.Category).filter(models.Category.is_active == True)
    
    if featured_only:
        query = query.filter(models.Category.is_featured == True)
    
    categories = query.order_by(models.Category.display_order).offset(skip).limit(limit).all()
    return categories

@router.post("/", response_model=schemas.Category)
def create_category(
    *,
    db: Session = Depends(deps.get_db),
    category_in: schemas.CategoryCreate,
    current_user: models.User = Depends(deps.get_current_active_user),
) -> Any:
    """Create new category (admin only)"""
    if current_user.role != models.UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Not enough permissions")
    
    # Generate slug
    slug = category_in.name.lower().replace(" ", "-")
    
    category = models.Category(
        **category_in.dict(),
        slug=slug
    )
    db.add(category)
    db.commit()
    db.refresh(category)
    return category

# app/api/api_v1/endpoints/leads.py
from typing import Any, List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from datetime import datetime

from app import models, schemas
from app.api import deps
from app.core.monitoring import metrics

router = APIRouter()

@router.get("/", response_model=List[schemas.Lead])
def read_leads(
    db: Session = Depends(deps.get_db),
    skip: int = 0,
    limit: int = 100,
    status: str = None,
    current_user: models.User = Depends(deps.get_current_active_user),
) -> Any:
    """Get leads for current vendor"""
    if current_user.role != models.UserRole.VENDOR:
        raise HTTPException(status_code=403, detail="Only vendors can view leads")
    
    query = db.query(models.Lead).filter(models.Lead.vendor_id == current_user.id)
    
    if status:
        query = query.filter(models.Lead.status == status)
    
    leads = query.order_by(models.Lead.created_at.desc()).offset(skip).limit(limit).all()
    return leads

@router.put("/{lead_id}", response_model=schemas.Lead)
def update_lead(
    *,
    db: Session = Depends(deps.get_db),
    lead_id: int,
    lead_in: schemas.LeadUpdate,
    current_user: models.User = Depends(deps.get_current_active_user),
) -> Any:
    """Update lead status and details"""
    lead = db.query(models.Lead).filter(models.Lead.id == lead_id).first()
    
    if not lead:
        raise HTTPException(status_code=404, detail="Lead not found")
    
    if lead.vendor_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    update_data = lead_in.dict(exclude_unset=True)
    
    # Track status changes
    old_status = lead.status
    
    for field, value in update_data.items():
        setattr(lead, field, value)
    
    # Update timestamps based on status
    if "status" in update_data:
        if update_data["status"] == models.LeadStatus.WON:
            lead.actual_close_date = datetime.utcnow()
            
            # Update referral status
            referral = db.query(models.Referral).filter(
                models.Referral.id == lead.referral_id
            ).first()
            referral.status = models.ReferralStatus.COMPLETED
            referral.completed_at = datetime.utcnow()
    
    # Log activity
    activity = models.LeadActivity(
        lead_id=lead_id,
        activity_type="status_change",
        description=f"Status changed from {old_status} to {lead.status}"
    )
    db.add(activity)
    
    db.commit()
    db.refresh(lead)
    
    metrics.increment("leads.updated", tags={"status": lead.status.value})
    return lead

# app/api/api_v1/endpoints/analytics.py
from typing import Any
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from datetime import datetime, timedelta

from app import models, schemas
from app.api import deps
from app.services.analytics_service import AnalyticsService

router = APIRouter()

@router.get("/overview", response_model=schemas.AnalyticsOverview)
def get_analytics_overview(
    db: Session = Depends(deps.get_db),
    current_user: models.User = Depends(deps.get_current_active_user),
) -> Any:
    """Get analytics overview (admin only)"""
    if current_user.role != models.UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    analytics = AnalyticsService(db)
    
    # Get latest metrics
    latest_metrics = db.query(models.SystemMetrics).order_by(
        models.SystemMetrics.metric_date.desc()
    ).first()
    
    if not latest_metrics:
        # Calculate on the fly if no metrics stored
        analytics.collect_daily_metrics()
        latest_metrics = db.query(models.SystemMetrics).order_by(
            models.SystemMetrics.metric_date.desc()
        ).first()
    
    conversion_rate = 0
    if latest_metrics.total_referrals > 0:
        conversion_rate = (latest_metrics.completed_referrals / latest_metrics.total_referrals) * 100
    
    return schemas.AnalyticsOverview(
        total_users=latest_metrics.total_users,
        active_users_30d=latest_metrics.active_users,
        total_referrals=latest_metrics.total_referrals,
        completed_referrals=latest_metrics.completed_referrals,
        conversion_rate=conversion_rate,
        total_revenue=latest_metrics.total_revenue,
        mrr=latest_metrics.mrr,
        arr=latest_metrics.arr
    )

@router.get("/referrals", response_model=schemas.ReferralAnalytics)
def get_referral_analytics(
    db: Session = Depends(deps.get_db),
    current_user: models.User = Depends(deps.get_current_active_user),
) -> Any:
    """Get referral analytics"""
    # Implementation for referral analytics
    pass

# Add more imports to app/schemas/token.py
from datetime import datetime