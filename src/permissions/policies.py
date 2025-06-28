"""Casbin Policies Management Module

This module provides functions to manage Casbin policies programmatically, allowing dynamic updates to access
control rules at runtime. While static policies can be defined in a policy file (e.g., policy.csv), this module
enables the application to add or remove policies dynamically based on user actions, administrative changes, or
other runtime conditions.

Dynamic policy management is particularly useful for applications where permissions need to change frequently or
be customized per user or tenant without requiring a restart or manual file updates. This module interacts with
the Casbin enforcer to apply these changes immediately.

**Security Note**: Dynamic policy updates must be strictly validated and audited to prevent privilege escalation
or policy injection attacks (OWASP A01:2021 - Broken Access Control). Always sanitize inputs and log policy
changes for audit trails. Consider restricting dynamic updates to administrative roles and using persistent
storage for production environments to ensure policy integrity across restarts.

Functions:
    add_policy: Adds a new policy to allow a subject to perform an action on a resource.
    remove_policy: Removes a policy to revoke access for a subject on a resource.

Note: Policies added programmatically are in-memory by default unless persisted to a storage adapter (e.g.,
database). For permanent changes, consider integrating a Casbin adapter for policy persistence.
"""

import logging

from .enforcer import get_enforcer

# Configure logging for policy management events
logger = logging.getLogger(__name__)


def _validate_policy_input(
    subject: str,
    object: str,
    action: str,
    sub_dept: str = "*",
    sub_loc: str = "*",
    time_of_day: str = "*",
) -> None:
    """Validate policy input parameters to prevent malformed or malicious data.

    Args:
        subject (str): The subject (e.g., role or user ID) to validate.
        object (str): The object (e.g., resource or endpoint) to validate.
        action (str): The action (e.g., 'GET', 'POST') to validate.
        sub_dept (str): The department attribute for ABAC, defaults to wildcard.
        sub_loc (str): The location attribute for ABAC, defaults to wildcard.
        time_of_day (str): The time of day attribute for ABAC, defaults to wildcard.

    Raises:
        ValueError: If any input is empty, contains invalid characters, or exceeds length limits.

    """
    if not all([subject, object, action]):
        raise ValueError("Policy parameters (subject, object, action) cannot be empty")

    max_length = 255
    for param, name in [
        (subject, "subject"),
        (object, "object"),
        (action, "action"),
        (sub_dept, "sub_dept"),
        (sub_loc, "sub_loc"),
        (time_of_day, "time_of_day"),
    ]:
        if len(param) > max_length:
            raise ValueError(f"Policy {name} exceeds maximum length of {max_length} characters")
        if any(char in param for char in ["\n", "\r", "\t"]):
            raise ValueError(f"Policy {name} contains invalid control characters")


def add_policy(
    subject: str,
    object: str,
    action: str,
    sub_dept: str = "*",
    sub_loc: str = "*",
    time_of_day: str = "*",
) -> bool:
    """Add a policy to allow a subject to perform an action on an object.

        This function creates a new access control rule (policy) that grants permission to a subject (e.g., a user
        or role) to perform a specified action on a given object (e.g., an API endpoint or resource). The policy is
        added to the Casbin enforcer's in-memory policy set and takes effect immediately for subsequent permission
        checks.

        **Security Note**: Input validation is performed to prevent policy injection. Policy additions are logged for
    audit purposes. Ensure that only authorized users can add policies to prevent privilege escalation.

    Args:
            subject (str): The subject (e.g., role like 'admin' or user ID) to which the policy applies.
            object (str): The object (e.g., resource or endpoint like '/health') to which access is granted.
            action (str): The action (e.g., 'GET', 'POST') that the subject is allowed to perform.
            sub_dept (str): The department attribute for ABAC, defaults to wildcard "*".
            sub_loc (str): The location attribute for ABAC, defaults to wildcard "*".
            time_of_day (str): The time of day attribute for ABAC, defaults to wildcard "*".

    Returns:
            bool: True if the policy was added successfully, False if it already exists or the operation failed.

    Raises:
            ValueError: If the input parameters are invalid or malformed.

    Example:
            To allow the 'editor' role to access '/reports' with GET:
            `add_policy('editor', '/reports', 'GET')`

    """
    _validate_policy_input(subject, object, action, sub_dept, sub_loc, time_of_day)
    enforcer = get_enforcer()
    success = enforcer.add_policy(subject, object, action, sub_dept, sub_loc, time_of_day)
    if success:
        logger.info(
            f"Policy added: {subject} can {action} on {object} with dept={sub_dept}, loc={sub_loc}, time={time_of_day}"
        )
    return success


def remove_policy(
    subject: str,
    object: str,
    action: str,
    sub_dept: str = "*",
    sub_loc: str = "*",
    time_of_day: str = "*",
) -> bool:
    """Remove a policy to deny a subject from performing an action on an object.

    This function removes an existing access control rule (policy) that previously granted permission to a subject
    to perform a specified action on a given object. Removing a policy effectively revokes access for the subject
    unless another policy or role inheritance grants the same permission.

    **Security Note**: Policy removals are logged for audit purposes. Ensure that policy removal does not
    inadvertently revoke critical access for administrative roles. Validate inputs to prevent unintended policy
    modifications.

    Args:
        subject (str): The subject (e.g., role like 'admin' or user ID) from which the policy is removed.
        object (str): The object (e.g., resource or endpoint like '/health') from which access is revoked.
        action (str): The action (e.g., 'GET', 'POST') that the subject is no longer allowed to perform.
        sub_dept (str): The department attribute for ABAC, defaults to wildcard "*".
        sub_loc (str): The location attribute for ABAC, defaults to wildcard "*".
        time_of_day (str): The time of day attribute for ABAC, defaults to wildcard "*".

    Returns:
        bool: True if the policy was removed successfully, False if it did not exist or the operation failed.

    Raises:
        ValueError: If the input parameters are invalid or malformed.

    Example:
        To revoke the 'editor' role's access to '/reports' with GET:
        `remove_policy('editor', '/reports', 'GET')`

    """
    _validate_policy_input(subject, object, action, sub_dept, sub_loc, time_of_day)
    enforcer = get_enforcer()
    success = enforcer.remove_policy(subject, object, action, sub_dept, sub_loc, time_of_day)
    if success:
        logger.info(
            f"Policy removed: {subject} can no longer {action} on {object} with dept={sub_dept}, loc={sub_loc}, time={time_of_day}"
        )
    return success
