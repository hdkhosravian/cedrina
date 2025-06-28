"""Admin API Request and Response Schemas

This module defines Pydantic schemas for admin policy management endpoints.
These schemas ensure proper request validation and consistent response formats.
"""

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class PolicyRequest(BaseModel):
    """Request schema for adding/removing policies."""

    subject: str = Field(
        ..., description="The subject (e.g., role) for the policy", min_length=1, max_length=255
    )
    object: str = Field(
        ..., description="The resource/object for the policy", min_length=1, max_length=255
    )
    action: str = Field(..., description="The action for the policy", min_length=1, max_length=255)
    sub_dept: Optional[str] = Field(
        None, description="Department attribute for ABAC", max_length=255
    )
    sub_loc: Optional[str] = Field(None, description="Location attribute for ABAC", max_length=255)
    time_of_day: Optional[str] = Field(
        None, description="Time of day attribute for ABAC", max_length=255
    )


class PolicyResponse(BaseModel):
    """Response schema for policy operations."""

    message: str = Field(..., description="Operation result message")
    subject: str = Field(..., description="The subject of the policy")
    object: str = Field(..., description="The resource/object of the policy")
    action: str = Field(..., description="The action of the policy")
    attributes: Optional[Dict[str, str]] = Field(None, description="ABAC attributes")


class PolicyListResponse(BaseModel):
    """Response schema for listing policies."""

    policies: List[Dict[str, Any]] = Field(..., description="List of policies")
    count: int = Field(..., description="Total number of policies")
