from pydantic import BaseModel, Field, field_validator
from typing import Optional, Literal
import re
from datetime import datetime, timezone


class ThreatIntel(BaseModel):
    # Enforce data intergrity for alert title
    title: str = Field(
        ...,
        min_length=3,
        max_length=200,
        description="The title of the threat intelligence entry",
    )

    # Restrict severity to a standard 1-5 scale
    severity: int = Field(..., ge=1, le=5, description="Risk level (1-5)")

    # Store indicator value and its type (e.g., IP, domain, etc.)
    ioc_value: str = Field(..., description="Indicator value")
    ioc_type: Literal["ipv4", "ipv6", "domain", "url", "sha256", "md5"] = Field(
        ..., description="Indicator type"
    )

    source: Literal["virustotal", "otx", "manual", "misp"] = Field(
        default="manual", description="Intelligence source"
    )

    confidence: int = Field(default=50, ge=0, le=100, description="Confidence score")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @field_validator("ioc_value")
    @classmethod
    def validate_ioc_format(cls, v: str) -> str:
        v = v.strip()
        # Ensure the IOC is not empty and meets minimum length.
        if not v or len(v) < 3:
            raise ValueError("IOC format is invalid: too short")
        return v
