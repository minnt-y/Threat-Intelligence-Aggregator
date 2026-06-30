from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional, List
from enum import Enum


# ========== Enums(Business Constraints) ===========
class IOCType(str, Enum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    CVE = "cve"


class RiskLevel(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class Confidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


# =========== Source Schemas ============
class SourceBase(BaseModel):
    name: str
    description: Optional[str] = None
    api_endpoint: Optional[str] = None


class SourceCreate(SourceBase):
    pass


class SourceResponse(SourceBase):
    id: int

    class Config:
        from_attributes = True


# ========== IOC Schenmas ==========
class IOCBase(BaseModel):
    value: str = Field(
        ..., min_length=1, description="IOC value, e.g., IP, domain, hash"
    )
    type: IOCType = Field(..., description="IOC type")


class IOCCreate(IOCBase):
    pass


class IOCResponse(IOCBase):
    id: int
    first_seen: datetime
    last_seen: datetime

    class Config:
        from_attributes = True


# ========== Attribution Schemas ==========
class AttributionBase(BaseModel):
    actor_name: str = Field(..., min_length=1)
    confidence: Optional[Confidence] = Confidence.LOW
    reasons: Optional[List[str]] = None


class AttributionCreate(AttributionBase):
    ioc_id: int


class AttributionResponse(AttributionBase):
    id: int
    ioc_id: int
    created_at: datetime

    class Config:
        from_attributes = True


# ========== Alert Schemas ==========
class AlertBase(BaseModel):
    risk_level: RiskLevel
    risk_score: float = Field(default=0.0, ge=0.0, le=100.0)
    raw_data: Optional[dict] = None


class AlertCreate(AlertBase):
    ioc_id: int
    source_id: int


class AlertResponse(AlertBase):
    id: int
    created_at: datetime
    ioc: IOCResponse
    source: SourceResponse

    class Config:
        from_attributes = True


# =========== Nested Schemas (With Relationships) ===========
class IOCWithAlerts(IOCResponse):
    alerts: List[AlertResponse] = []
    attributions: List[AttributionResponse] = []


class SourceWithAlerts(SourceResponse):
    alerts: List[AlertResponse] = []


# ========== Report / Statistics ==========
class RiskReport(BaseModel):
    total_alerts: int
    high_risk_count: int
    medium_risk_count: int
    low_risk_count: int
    top_threat_actors: List[dict]
    recent_iocs: List[IOCResponse]


class TrendData(BaseModel):
    date: str
    count: int
    risk_level: str
