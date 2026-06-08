from pydantic import BaseModel, Field, field_validator
from typing import Optional


class ThreatIntel(BaseModel):
    # Enforce data intergrity for alert title
    title: str = Field(..., description="The title of the threat intelligence entry")

    # Restrict severity to a standard 1-5 scale
    severity: int = Field(..., ge=1, le=5, description="Risk level (1-5)")

    # Store indocator value and its type (e.g., IP, domain)
    ioc_value: str = Field(..., description="The indicator value")
    ioc_type: str = Field(..., description="The type of the indicator")

    @field_validator("ioc_value")
    @classmethod
    def validate_ioc_length(cls, v: str) -> str:
        # Ensure the IOC is not empty and meets minimum length.
        if not v or len(v) < 3:
            raise ValueError("IOC format is invalid:too short")
        return v
