"""Admin Policy Management Endpoints

This module provides API endpoints for managing Casbin policies dynamically.
These endpoints are restricted to admin roles to prevent unauthorized access.
Rate limiting is applied to prevent abuse or denial-of-service attacks.

**Security Note**: Access to these endpoints is strictly controlled to prevent
privilege escalation (OWASP A01:2021 - Broken Access Control). All operations
are logged for audit purposes, and inputs are validated to prevent injection.
Rate limiting mitigates DoS risks (OWASP A03:2021 - Injection mitigation).
"""

from fastapi import APIRouter, Depends, HTTPException, Request, status

from src.core.dependencies.auth import get_current_user
from src.core.rate_limiting.ratelimiter import get_limiter
from src.domain.entities.user import User
from src.domain.services.security.policy import PolicyService
from src.permissions.dependencies import check_permission
from src.permissions.enforcer import get_enforcer

from .schemas import PolicyListResponse, PolicyRequest, PolicyResponse

router = APIRouter(tags=["admin", "policies"])

# Use centralized rate limiter for consistency
limiter = get_limiter()


def get_policy_service(enforcer=Depends(get_enforcer)) -> PolicyService:
    """Dependency to provide PolicyService instance.

    Args:
        enforcer: The Casbin enforcer instance.

    Returns:
        PolicyService: The policy management service.

    """
    return PolicyService(enforcer)


@router.post(
    "/policies/add",
    dependencies=[Depends(check_permission("/admin/policies", "POST"))],
    response_model=PolicyResponse,
)
@limiter.limit("50/minute")
async def add_policy(
    policy_request: PolicyRequest,
    request: Request,
    policy_service: PolicyService = Depends(get_policy_service),
    current_user: User = Depends(get_current_user),
):
    """Add a new policy to grant access.

    Args:
        policy_request: The policy request containing subject, object, action, and optional ABAC attributes.
        request: The HTTP request for locale and client information.
        policy_service: The policy management service.
        current_user: The current authenticated user.

    Returns:
        PolicyResponse: Confirmation of policy addition.

    Raises:
        HTTPException: If policy addition fails or input is invalid.

    """
    locale = getattr(request.state, "language", "en")
    client_ip = request.client.host or "unknown"
    user_agent = request.headers.get("User-Agent", "unknown")
    performed_by = str(current_user.id) if current_user.id else "anonymous"

    # Extract ABAC attributes
    attributes = {}
    if policy_request.sub_dept:
        attributes["sub_dept"] = policy_request.sub_dept
    if policy_request.sub_loc:
        attributes["sub_loc"] = policy_request.sub_loc
    if policy_request.time_of_day:
        attributes["time_of_day"] = policy_request.time_of_day

    try:
        success = policy_service.add_policy(
            policy_request.subject,
            policy_request.object,
            policy_request.action,
            performed_by,
            client_ip,
            user_agent,
            attributes if attributes else None,
            locale,
        )
        if success:
            return PolicyResponse(
                message="Policy added successfully",
                subject=policy_request.subject,
                object=policy_request.object,
                action=policy_request.action,
                attributes=attributes if attributes else None,
            )
        else:
            return PolicyResponse(
                message="Policy already exists",
                subject=policy_request.subject,
                object=policy_request.object,
                action=policy_request.action,
                attributes=attributes if attributes else None,
            )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@router.post(
    "/policies/remove",
    dependencies=[Depends(check_permission("/admin/policies", "POST"))],
    response_model=PolicyResponse,
)
@limiter.limit("50/minute")
async def remove_policy(
    policy_request: PolicyRequest,
    request: Request,
    policy_service: PolicyService = Depends(get_policy_service),
    current_user: User = Depends(get_current_user),
):
    """Remove a policy to revoke access.

    Args:
        policy_request: The policy request containing subject, object, and action.
        request: The HTTP request for locale and client information.
        policy_service: The policy management service.
        current_user: The current authenticated user.

    Returns:
        PolicyResponse: Confirmation of policy removal.

    Raises:
        HTTPException: If policy removal fails or input is invalid.

    """
    locale = getattr(request.state, "language", "en")
    client_ip = request.client.host or "unknown"
    user_agent = request.headers.get("User-Agent", "unknown")
    performed_by = str(current_user.id) if current_user.id else "anonymous"
    try:
        success = policy_service.remove_policy(
            policy_request.subject,
            policy_request.object,
            policy_request.action,
            performed_by,
            client_ip,
            user_agent,
            locale,
        )
        if success:
            return PolicyResponse(
                message="Policy removed successfully",
                subject=policy_request.subject,
                object=policy_request.object,
                action=policy_request.action,
            )
        else:
            return PolicyResponse(
                message="Policy not found",
                subject=policy_request.subject,
                object=policy_request.object,
                action=policy_request.action,
            )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@router.get(
    "/policies",
    dependencies=[Depends(check_permission("/admin/policies", "GET"))],
    response_model=PolicyListResponse,
)
@limiter.limit("100/minute")
async def list_policies(
    request: Request,
    policy_service: PolicyService = Depends(get_policy_service),
    current_user: User = Depends(get_current_user),
):
    """Retrieve all current policies.

    Args:
        request: The HTTP request for locale information.
        policy_service: The policy management service.
        current_user: The current authenticated user.

    Returns:
        PolicyListResponse: List of policies with attributes.

    Raises:
        HTTPException: If retrieval fails.

    """
    locale = getattr(request.state, "language", "en")
    try:
        policies = policy_service.get_policies(locale)
        return PolicyListResponse(policies=policies, count=len(policies))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))
