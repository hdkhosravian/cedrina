"""
Casbin Enforcer Module

This module initializes the Casbin enforcer, which is the core component responsible for evaluating and enforcing
access control policies in the application. The enforcer uses a model configuration and a set of policies to
determine whether a subject (e.g., a user or role) is allowed to perform a specific action on a given resource.

Casbin supports multiple access control models such as Role-Based Access Control (RBAC), Attribute-Based Access
Control (ABAC), and more, making it highly flexible for complex permission requirements. In this application, it
is primarily used for RBAC to restrict access to certain API endpoints based on user roles.

The enforcer is initialized as a singleton instance to ensure consistent policy enforcement across the application.
It loads the model and policy files defined in the config module during startup.

**Security Note**: The enforcer must be initialized with trusted model and policy files to prevent policy tampering
(OWASP A01:2021 - Broken Access Control). Ensure that policy updates are audited and validated to prevent
unauthorized access. Consider using a persistent storage adapter for production environments to maintain policy
integrity across restarts.

Functions:
    get_enforcer: Returns the initialized Casbin enforcer instance for use in permission checks.
"""

import casbin
from .config import MODEL_PATH, POLICY_PATH

# Initialize the Casbin enforcer with model and policy as a singleton
# The 'True' parameter enables auto-loading of policies if the policy file changes
enforcer: casbin.Enforcer = casbin.Enforcer(str(MODEL_PATH), str(POLICY_PATH), True)

def get_enforcer() -> casbin.Enforcer:
    """
    Get the Casbin enforcer instance.

    This function provides access to the singleton Casbin enforcer instance, which is used throughout the
    application to check permissions. The enforcer evaluates requests against the loaded model and policies to
    determine access rights.

    **Design Pattern**: Singleton pattern is used here to ensure a single instance of the enforcer is used across
    the application, maintaining consistency in policy enforcement.

    Returns:
        casbin.Enforcer: The initialized Casbin enforcer for permission checks.
    """
    return enforcer 