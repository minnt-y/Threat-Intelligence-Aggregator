from pydantic import BaseModel, Field, field_validator
from typing import Optional


class ThreatIntel(BaseModel):
    """
    Data schema for threat intelligence objects.
    Enforce data integrity and type safety.
    """

    title: str = Field(..., description="The title of the threat intelligence entry")
    severity: int = Field(..., ge=1, le=5, description="Risk level (1-5)")
    ioc: str = Field(
        ..., description="Indicator of Compromise(IP address, domain, etc.)"
    )

    @field_validator("ioc")
    @classmethod
    def validate_ioc_length(cls, v: str) -> str:
        """Ensure the IOC is not empty and meets minimum length."""
        if not v or len(v) < 3:
            raise ValueError("IOC format is invalid: too short")
        return v
