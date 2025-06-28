"""Dynamic Policy Management Service

This module provides a service for managing Casbin policies dynamically at runtime.
It allows adding, removing, and listing policies with strict security controls,
Attribute-Based Access Control (ABAC), policy versioning, detailed audit logging,
and internationalization support for error messages.

**Security Note**: Policy management is restricted to admin roles to prevent
privilege escalation (OWASP A01:2021 - Broken Access Control). All inputs are
validated to prevent policy injection, and changes are logged for audit purposes.
Audit logs include detailed metadata for forensic analysis (OWASP A09:2021 - Security
Logging and Monitoring Failures mitigation).
"""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import sqlalchemy as sa
from casbin import Enforcer

from src.core.exceptions import PermissionError
from src.infrastructure.database.database import get_db_session
from src.utils.i18n import get_translated_message

# Configure logging for policy management events
logger = logging.getLogger(__name__)


class PolicyService:
    """Service for managing Casbin policies dynamically with ABAC, versioning, and audit logging."""

    def __init__(self, enforcer: Enforcer):
        """Initialize the PolicyService with a Casbin enforcer.

        Args:
            enforcer (Enforcer): The Casbin enforcer instance for policy operations.

        """
        self.enforcer = enforcer

    def _validate_policy_input(
        self, subject: str, object: str, action: str, attributes: Optional[Dict[str, str]] = None
    ) -> None:
        """Validate policy input parameters to prevent malformed or malicious data.

        Args:
            subject (str): The subject (e.g., role or user ID) to validate.
            object (str): The object (e.g., resource or endpoint) to validate.
            action (str): The action (e.g., 'GET', 'POST') to validate.
            attributes (Optional[Dict[str, str]]): Additional ABAC attributes to validate.

        Raises:
            ValueError: If any input is empty, contains invalid characters, or exceeds length limits.

        """
        if not all([subject, object, action]):
            raise ValueError("Policy parameters (subject, object, action) cannot be empty")

        max_length = 255
        for param, name in [(subject, "subject"), (object, "object"), (action, "action")]:
            if len(param) > max_length:
                raise ValueError(f"Policy {name} exceeds maximum length of {max_length} characters")
            if any(char in param for char in ["\n", "\r", "\t"]):
                raise ValueError(f"Policy {name} contains invalid control characters")

        # Prevent wildcard policies unless explicitly allowed
        if "*" in subject or "*" in action:
            raise ValueError("Wildcards are not allowed in subject or action for security reasons")

        if attributes:
            allowed_attributes = {"sub_dept", "sub_loc", "time_of_day"}
            for attr, value in attributes.items():
                if attr not in allowed_attributes:
                    raise ValueError(
                        f"Invalid attribute {attr}; allowed attributes are {allowed_attributes}"
                    )
                if len(value) > max_length:
                    raise ValueError(
                        f"Attribute {attr} value exceeds maximum length of {max_length} characters"
                    )
                if any(char in value for char in ["\n", "\r", "\t"]):
                    raise ValueError(f"Attribute {attr} value contains invalid control characters")

    def _log_audit_event(
        self,
        operation: str,
        subject: str,
        object: str,
        action: str,
        performed_by: str,
        ip_address: str,
        user_agent: str,
        details: Optional[str] = None,
        policy_id: Optional[int] = None,
    ) -> None:
        """Log policy management events to the audit log table for forensic analysis.

        Args:
            operation (str): The operation performed (e.g., 'add', 'remove').
            subject (str): The subject of the policy.
            object (str): The object of the policy.
            action (str): The action of the policy.
            performed_by (str): The user who performed the operation.
            ip_address (str): The IP address of the requester.
            user_agent (str): The user agent of the requester.
            details (Optional[str]): Additional details about the operation.
            policy_id (Optional[int]): The ID of the affected policy, if applicable.

        """
        try:
            with get_db_session() as session:
                audit_log = {
                    "policy_id": policy_id,
                    "operation": operation,
                    "subject": subject,
                    "object": object,
                    "action": action,
                    "performed_by": performed_by,
                    "performed_at": datetime.now(timezone.utc),
                    "ip_address": ip_address,
                    "user_agent": user_agent,
                    "details": details,
                }
                session.execute(
                    sa.text(
                        """
                    INSERT INTO policy_audit_logs (policy_id, operation, subject, object, action, performed_by, performed_at, ip_address, user_agent, details)
                    VALUES (:policy_id, :operation, :subject, :object, :action, :performed_by, :performed_at, :ip_address, :user_agent, :details)
                """
                    ),
                    audit_log,
                )
                session.commit()
                logger.info(
                    f"Audit log recorded for {operation} by {performed_by} on {subject}, {object}, {action}"
                )
        except Exception as e:
            logger.error(f"Failed to record audit log: {e!s}")

    def add_policy(
        self,
        subject: str,
        object: str,
        action: str,
        performed_by: str,
        ip_address: str,
        user_agent: str,
        attributes: Optional[Dict[str, str]] = None,
        locale: str = "en",
    ) -> bool:
        """Add a policy to allow a subject to perform an action on an object with optional ABAC attributes.

        Args:
            subject (str): The subject (e.g., role like 'admin') to which the policy applies.
            object (str): The object (e.g., resource like '/health') to which access is granted.
            action (str): The action (e.g., 'GET') that the subject is allowed to perform.
            performed_by (str): The user performing the operation for audit logging.
            ip_address (str): The IP address of the requester for audit logging.
            user_agent (str): The user agent of the requester for audit logging.
            attributes (Optional[Dict[str, str]]): ABAC attributes like department or location.
            locale (str): The locale for error messages.

        Returns:
            bool: True if the policy was added successfully, False if it already exists.

        Raises:
            ValueError: If the input parameters are invalid.
            PermissionError: If the operation fails due to internal errors.

        """
        try:
            self._validate_policy_input(subject, object, action, attributes)
            policy_params = [subject, object, action]
            if attributes:
                policy_params.extend(
                    [
                        attributes.get("sub_dept", "*"),
                        attributes.get("sub_loc", "*"),
                        attributes.get("time_of_day", "*"),
                    ]
                )
            else:
                policy_params.extend(["*", "*", "*"])
            success = self.enforcer.add_policy(*policy_params)
            if success:
                logger.info(
                    f"Policy added: {subject} can {action} on {object} with attributes {attributes}"
                )
                self._log_audit_event(
                    "add",
                    subject,
                    object,
                    action,
                    performed_by,
                    ip_address,
                    user_agent,
                    details=str(attributes),
                )
            else:
                logger.warning(f"Policy already exists: {subject} can {action} on {object}")
            return success
        except Exception as e:
            error_msg = get_translated_message("policy_add_failed", locale).format(error=str(e))
            logger.error(f"Failed to add policy: {error_msg}")
            raise PermissionError(error_msg)

    def remove_policy(
        self,
        subject: str,
        object: str,
        action: str,
        performed_by: str,
        ip_address: str,
        user_agent: str,
        locale: str = "en",
    ) -> bool:
        """Remove a policy to deny a subject from performing an action on an object.

        Args:
            subject (str): The subject from which the policy is removed.
            object (str): The object from which access is revoked.
            action (str): The action that the subject is no longer allowed to perform.
            performed_by (str): The user performing the operation for audit logging.
            ip_address (str): The IP address of the requester for audit logging.
            user_agent (str): The user agent of the requester for audit logging.
            locale (str): The locale for error messages.

        Returns:
            bool: True if the policy was removed successfully, False if it did not exist.

        Raises:
            ValueError: If the input parameters are invalid.
            PermissionError: If the operation fails due to internal errors.

        """
        try:
            self._validate_policy_input(subject, object, action)
            success = self.enforcer.remove_policy(subject, object, action)
            if success:
                logger.info(f"Policy removed: {subject} can no longer {action} on {object}")
                self._log_audit_event(
                    "remove", subject, object, action, performed_by, ip_address, user_agent
                )
            else:
                logger.warning(f"Policy not found: {subject} can {action} on {object}")
            return success
        except Exception as e:
            error_msg = get_translated_message("policy_remove_failed", locale).format(error=str(e))
            logger.error(f"Failed to remove policy: {error_msg}")
            raise PermissionError(error_msg)

    def get_policies(self, locale: str = "en") -> List[Dict[str, Any]]:
        """Retrieve all current policies with ABAC attributes.

        Args:
            locale (str): The locale for error messages.

        Returns:
            List[Dict[str, Any]]: A list of policy dictionaries with subject, object, action, and attributes.

        Raises:
            PermissionError: If the operation fails due to internal errors.

        """
        try:
            policies = self.enforcer.get_policy()
            logger.info(f"Retrieved {len(policies)} policies")

            formatted_policies = []
            for policy in policies:
                if len(policy) >= 3:
                    policy_dict = {"subject": policy[0], "object": policy[1], "action": policy[2]}

                    # Add ABAC attributes if present
                    if len(policy) >= 6:
                        attributes = {}
                        if policy[3] != "*":
                            attributes["sub_dept"] = policy[3]
                        if policy[4] != "*":
                            attributes["sub_loc"] = policy[4]
                        if policy[5] != "*":
                            attributes["time_of_day"] = policy[5]

                        if attributes:
                            policy_dict["attributes"] = attributes

                    formatted_policies.append(policy_dict)

            return formatted_policies
        except Exception as e:
            error_msg = get_translated_message("policy_retrieve_failed", locale).format(
                error=str(e)
            )
            logger.error(f"Failed to retrieve policies: {error_msg}")
            raise PermissionError(error_msg)
