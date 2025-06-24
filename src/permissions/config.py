"""
Casbin Configuration Module

This module defines the configuration paths for the Casbin access control system, which is used to manage permissions
and enforce role-based access control (RBAC) in the application. Casbin is a powerful and flexible library that
supports various access control models including RBAC, ABAC (Attribute-Based Access Control), and more.

The paths defined here point to the model configuration file and the policy file, which together dictate how
permissions are evaluated and enforced. These files are critical for the correct functioning of the access
control system.

**Security Note**: Ensure that the model and policy files are protected from unauthorized access or modification,
as tampering with these files could lead to privilege escalation or denial of access. Avoid using user-provided
input directly in file paths to prevent path traversal attacks (OWASP A01:2021 - Broken Access Control).

Attributes:
    MODEL_PATH (Path): The absolute path to the Casbin model configuration file (model.conf). This file defines
the structure of access control rules, including request definitions, policy definitions, and matching logic.
    POLICY_PATH (Path): The absolute path to the Casbin policy file (policy.csv). This file contains the specific
rules or policies that grant or deny access to resources based on roles or users.
"""

from pathlib import Path

# Define paths for Casbin model and policy files using pathlib for cross-platform compatibility
BASE_DIR = Path(__file__).parent.resolve()
MODEL_PATH: Path = BASE_DIR / "model.conf"
POLICY_PATH: Path = BASE_DIR / "policy.csv" 