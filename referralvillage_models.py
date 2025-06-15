# models.py - Complete SQLAlchemy models for ReferralVillage

from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, Text, ForeignKey, Enum, JSON, DECIMAL
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.sql import func
from datetime import datetime
import enum

Base = declarative_base()

# Enums
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

# Main Models
class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(Enum(UserRole), default=UserRole.AGENT, nullable=False)
    
    # Profile Information
    first_name = Column(String(100), nullable=False)
    last_name = Column(String(100), nullable=False)
    company_name = Column(String(255))
    phone = Column(String(20))
    avatar_url = Column(String(500))
    bio = Column(Text)
    
    # Stripe Integration
    stripe_customer_id = Column(String(255), unique=True)
    stripe_account_id = Column(String(255), unique=True)  # For vendors receiving payouts
    
    # Settings
    notification_preferences = Column(JSON, default=lambda: {
        "email": True,
        "sms": False,
        "in_app": True
    })
    
    # Status & Timestamps
    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)
    last_login = Column(DateTime)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    
    # Relationships
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
    icon = Column(String(50))  # Icon class or emoji
    parent_id = Column(Integer, ForeignKey("categories.id"))
    
    # SEO & Display
    meta_title = Column(String(255))
    meta_description = Column(Text)
    is_featured = Column(Boolean, default=False)
    display_order = Column(Integer, default=0)
    
    # Status
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    
    # Relationships
    parent = relationship("Category", remote_side=[id])
    referrals = relationship("Referral", back_populates="category")

class Referral(Base):
    __tablename__ = "referrals"
    
    id = Column(Integer, primary_key=True)
    creator_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    assigned_vendor_id = Column(Integer, ForeignKey("users.id"))
    category_id = Column(Integer, ForeignKey("categories.id"), nullable=False)
    
    # Referral Details
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    budget_min = Column(DECIMAL(10, 2))
    budget_max = Column(DECIMAL(10, 2))
    commission_type = Column(String(50), default="percentage")  # percentage or fixed
    commission_value = Column(DECIMAL(10, 2), nullable=False)  # Percentage (0-100) or fixed amount
    
    # Client Information
    client_name = Column(String(255), nullable=False)
    client_email = Column(String(255), nullable=False)
    client_phone = Column(String(20))
    client_company = Column(String(255))
    
    # Location & Preferences
    location = Column(String(255))
    preferred_contact_method = Column(String(50), default="email")
    urgency = Column(String(50), default="normal")  # low, normal, high, urgent
    
    # AI Matching
    ai_match_score = Column(Float)  # 0-100 score from AI matching
    ai_match_reasons = Column(JSON)  # Reasons for the match
    matching_criteria = Column(JSON)  # Specific criteria for matching
    
    # Status & Timestamps
    status = Column(Enum(ReferralStatus), default=ReferralStatus.DRAFT)
    expires_at = Column(DateTime)
    matched_at = Column(DateTime)
    completed_at = Column(DateTime)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    
    # Relationships
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
    
    # Lead Progress
    status = Column(Enum(LeadStatus), default=LeadStatus.NEW)
    notes = Column(Text)
    next_action = Column(String(255))
    next_action_date = Column(DateTime)
    
    # Deal Information
    deal_value = Column(DECIMAL(10, 2))
    probability = Column(Integer)  # 0-100 percentage
    expected_close_date = Column(DateTime)
    actual_close_date = Column(DateTime)
    
    # Communication Log
    last_contact_date = Column(DateTime)
    contact_count = Column(Integer, default=0)
    
    # Timestamps
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    
    # Relationships
    referral = relationship("Referral", back_populates="leads")
    vendor = relationship("User", back_populates="leads")
    activities = relationship("LeadActivity", back_populates="lead")

class LeadActivity(Base):
    __tablename__ = "lead_activities"
    
    id = Column(Integer, primary_key=True)
    lead_id = Column(Integer, ForeignKey("leads.id"), nullable=False)
    
    activity_type = Column(String(50), nullable=False)  # call, email, meeting, note
    description = Column(Text)
    outcome = Column(String(255))
    
    created_at = Column(DateTime, default=func.now())
    
    # Relationships
    lead = relationship("Lead", back_populates="activities")

class ContractorVerification(Base):
    __tablename__ = "contractor_verifications"
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    
    # Verification Details
    verification_type = Column(String(50), nullable=False)  # license, insurance, certification
    document_url = Column(String(500))
    document_number = Column(String(255))
    issuing_authority = Column(String(255))
    
    # Status
    status = Column(Enum(VerificationStatus), default=VerificationStatus.PENDING)
    verified_by = Column(Integer, ForeignKey("users.id"))  # Admin who verified
    rejection_reason = Column(Text)
    
    # Dates
    issue_date = Column(DateTime)
    expiry_date = Column(DateTime)
    verified_at = Column(DateTime)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    
    # Relationships
    user = relationship("User", back_populates="verifications", foreign_keys=[user_id])

class CommissionPayout(Base):
    __tablename__ = "commission_payouts"
    
    id = Column(Integer, primary_key=True)
    referral_id = Column(Integer, ForeignKey("referrals.id"), nullable=False)
    payout_id = Column(Integer, ForeignKey("payouts.id"))
    
    # Commission Details
    commission_amount = Column(DECIMAL(10, 2), nullable=False)
    deal_value = Column(DECIMAL(10, 2), nullable=False)
    
    # Status
    is_paid = Column(Boolean, default=False)
    paid_at = Column(DateTime)
    
    created_at = Column(DateTime, default=func.now())
    
    # Relationships
    referral = relationship("Referral", back_populates="commission_payouts")
    payout = relationship("Payout", back_populates="commissions")

class Payout(Base):
    __tablename__ = "payouts"
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    
    # Payout Details
    amount = Column(DECIMAL(10, 2), nullable=False)
    currency = Column(String(3), default="USD")
    status = Column(Enum(PayoutStatus), default=PayoutStatus.PENDING)
    
    # Stripe Integration
    stripe_payout_id = Column(String(255), unique=True)
    stripe_transfer_id = Column(String(255), unique=True)
    
    # Processing
    processed_at = Column(DateTime)
    failed_reason = Column(Text)
    
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    
    # Relationships
    user = relationship("User", back_populates="payouts")
    commissions = relationship("CommissionPayout", back_populates="payout")

class Notification(Base):
    __tablename__ = "notifications"
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    
    # Notification Content
    type = Column(Enum(NotificationType), nullable=False)
    title = Column(String(255), nullable=False)
    message = Column(Text, nullable=False)
    data = Column(JSON)  # Additional context data
    
    # Status
    is_read = Column(Boolean, default=False)
    read_at = Column(DateTime)
    
    created_at = Column(DateTime, default=func.now())
    
    # Relationships
    user = relationship("User", back_populates="notifications")

class AnalyticsEvent(Base):
    __tablename__ = "analytics_events"
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    
    # Event Details
    event_type = Column(String(100), nullable=False, index=True)
    event_category = Column(String(100))
    event_data = Column(JSON)
    
    # Context
    ip_address = Column(String(45))
    user_agent = Column(String(500))
    session_id = Column(String(255))
    
    created_at = Column(DateTime, default=func.now(), index=True)
    
    # Relationships
    user = relationship("User", back_populates="analytics_events")

class SystemMetrics(Base):
    __tablename__ = "system_metrics"
    
    id = Column(Integer, primary_key=True)
    
    # Metrics
    metric_date = Column(DateTime, nullable=False, unique=True, index=True)
    total_users = Column(Integer, default=0)
    active_users = Column(Integer, default=0)
    total_referrals = Column(Integer, default=0)
    completed_referrals = Column(Integer, default=0)
    total_revenue = Column(DECIMAL(10, 2), default=0)
    total_commissions_paid = Column(DECIMAL(10, 2), default=0)
    
    # MRR Calculation
    mrr = Column(DECIMAL(10, 2), default=0)
    arr = Column(DECIMAL(10, 2), default=0)
    
    created_at = Column(DateTime, default=func.now())