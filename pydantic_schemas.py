# app/schemas/user.py
from typing import Optional, Dict
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
    avatar_url: Optional[str] = None
    notification_preferences: Optional[Dict] = None

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

class UserInDB(UserInDBBase):
    password_hash: str

# app/schemas/referral.py
from typing import Optional, List, Dict
from pydantic import BaseModel, Field
from datetime import datetime
from decimal import Decimal
from app.models import ReferralStatus

class ReferralBase(BaseModel):
    title: str
    description: str
    category_id: int
    budget_min: Optional[Decimal] = None
    budget_max: Optional[Decimal] = None
    commission_type: str = "percentage"
    commission_value: Decimal = Field(..., ge=0)
    client_name: str
    client_email: str
    client_phone: Optional[str] = None
    client_company: Optional[str] = None
    location: Optional[str] = None
    preferred_contact_method: str = "email"
    urgency: str = "normal"

class ReferralCreate(ReferralBase):
    matching_criteria: Optional[Dict] = None

class ReferralUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    status: Optional[ReferralStatus] = None
    assigned_vendor_id: Optional[int] = None

class ReferralInDBBase(ReferralBase):
    id: int
    creator_id: int
    assigned_vendor_id: Optional[int] = None
    status: ReferralStatus
    ai_match_score: Optional[float] = None
    ai_match_reasons: Optional[Dict] = None
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True

class Referral(ReferralInDBBase):
    pass

class ReferralWithMatches(Referral):
    potential_vendors: Optional[List[Dict]] = None

# app/schemas/lead.py
from typing import Optional
from pydantic import BaseModel
from datetime import datetime
from decimal import Decimal
from app.models import LeadStatus

class LeadBase(BaseModel):
    notes: Optional[str] = None
    next_action: Optional[str] = None
    next_action_date: Optional[datetime] = None

class LeadCreate(LeadBase):
    referral_id: int

class LeadUpdate(BaseModel):
    status: Optional[LeadStatus] = None
    notes: Optional[str] = None
    next_action: Optional[str] = None
    next_action_date: Optional[datetime] = None
    deal_value: Optional[Decimal] = None
    probability: Optional[int] = Field(None, ge=0, le=100)
    expected_close_date: Optional[datetime] = None

class LeadInDBBase(LeadBase):
    id: int
    referral_id: int
    vendor_id: int
    status: LeadStatus
    deal_value: Optional[Decimal] = None
    probability: Optional[int] = None
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True

class Lead(LeadInDBBase):
    pass

# app/schemas/payout.py
from typing import Optional, List
from pydantic import BaseModel
from datetime import datetime
from decimal import Decimal
from app.models import PayoutStatus

class PayoutBase(BaseModel):
    amount: Decimal = Field(..., gt=0)
    currency: str = "USD"

class PayoutCreate(PayoutBase):
    commission_ids: List[int]  # List of commission_payout IDs to include

class PayoutInDBBase(PayoutBase):
    id: int
    user_id: int
    status: PayoutStatus
    stripe_payout_id: Optional[str] = None
    processed_at: Optional[datetime] = None
    created_at: datetime
    
    class Config:
        from_attributes = True

class Payout(PayoutInDBBase):
    pass

# app/schemas/token.py
from typing import Optional
from pydantic import BaseModel

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenPayload(BaseModel):
    sub: Optional[int] = None

# app/schemas/category.py
from typing import Optional
from pydantic import BaseModel
from datetime import datetime

class CategoryBase(BaseModel):
    name: str
    description: Optional[str] = None
    icon: Optional[str] = None
    parent_id: Optional[int] = None
    is_featured: bool = False

class CategoryCreate(CategoryBase):
    pass

class CategoryUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    is_active: Optional[bool] = None
    is_featured: Optional[bool] = None

class CategoryInDBBase(CategoryBase):
    id: int
    slug: str
    is_active: bool
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True

class Category(CategoryInDBBase):
    pass

# app/schemas/analytics.py
from typing import Dict, List
from pydantic import BaseModel
from datetime import datetime
from decimal import Decimal

class AnalyticsOverview(BaseModel):
    total_users: int
    active_users_30d: int
    total_referrals: int
    completed_referrals: int
    conversion_rate: float
    total_revenue: Decimal
    mrr: Decimal
    arr: Decimal

class ReferralAnalytics(BaseModel):
    referrals_by_status: Dict[str, int]
    referrals_by_category: List[Dict]
    average_commission: Decimal
    average_deal_size: Decimal
    top_performers: List[Dict]

class RevenueAnalytics(BaseModel):
    revenue_by_month: List[Dict]
    commissions_paid: Decimal
    pending_commissions: Decimal
    average_payout_time: float

# app/schemas/verification.py
from typing import Optional
from pydantic import BaseModel
from datetime import datetime
from app.models import VerificationStatus

class VerificationBase(BaseModel):
    verification_type: str
    document_number: Optional[str] = None
    issuing_authority: Optional[str] = None
    issue_date: Optional[datetime] = None
    expiry_date: Optional[datetime] = None

class VerificationCreate(VerificationBase):
    document_url: str

class VerificationUpdate(BaseModel):
    status: Optional[VerificationStatus] = None
    rejection_reason: Optional[str] = None

class VerificationInDBBase(VerificationBase):
    id: int
    user_id: int
    status: VerificationStatus
    document_url: str
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True

class Verification(VerificationInDBBase):
    pass