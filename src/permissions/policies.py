"""
Casbin Policies Management Module

This module provides functions to manage Casbin policies programmatically, allowing dynamic updates to access
control rules at runtime. While static policies can be defined in a policy file (e.g., policy.csv), this module
enables the application to add or remove policies dynamically based on user actions, administrative changes, or
other runtime conditions.

Dynamic policy management is particularly useful for applications where permissions need to change frequently or
be customized per user or tenant without requiring a restart or manual file updates. This module interacts with
the Casbin enforcer to apply these changes immediately.

Functions:
    add_policy: Adds a new policy to allow a subject to perform an action on a resource.
    remove_policy: Removes a policy to revoke access for a subject on a resource.

Note: Policies added programmatically are in-memory by default unless persisted to a storage adapter (e.g.,
database). For permanent changes, consider integrating a Casbin adapter for policy persistence.
"""

from .enforcer import get_enforcer

def add_policy(subject: str, object: str, action: str) -> bool:
    """
    Add a policy to allow a subject to perform an action on an object.

    This function creates a new access control rule (policy) that grants permission to a subject (e.g., a user
    or role) to perform a specified action on a given object (e.g., an API endpoint or resource). The policy is
    added to the Casbin enforcer's in-memory policy set and takes effect immediately for subsequent permission
    checks.

    Args:
        subject (str): The subject (e.g., role like 'admin' or user ID) to which the policy applies.
        object (str): The object (e.g., resource or endpoint like '/health') to which access is granted.
        action (str): The action (e.g., 'GET', 'POST') that the subject is allowed to perform.

    Returns:
        bool: True if the policy was added successfully, False if it already exists or the operation failed.

    Example:
        To allow the 'editor' role to access '/reports' with GET:
        `add_policy('editor', '/reports', 'GET')`
    """
    enforcer = get_enforcer()
    return enforcer.add_policy(subject, object, action)

def remove_policy(subject: str, object: str, action: str) -> bool:
    """
    Remove a policy to deny a subject from performing an action on an object.

    This function removes an existing access control rule (policy) that previously granted permission to a subject
    to perform a specified action on a given object. Removing a policy effectively revokes access for the subject
    unless another policy or role inheritance grants the same permission.

    Args:
        subject (str): The subject (e.g., role like 'admin' or user ID) from which the policy is removed.
        object (str): The object (e.g., resource or endpoint like '/health') from which access is revoked.
        action (str): The action (e.g., 'GET', 'POST') that the subject is no longer allowed to perform.

    Returns:
        bool: True if the policy was removed successfully, False if it did not exist or the operation failed.

    Example:
        To revoke the 'editor' role's access to '/reports' with GET:
        `remove_policy('editor', '/reports', 'GET')`
    """
    enforcer = get_enforcer()
    return enforcer.remove_policy(subject, object, action) 