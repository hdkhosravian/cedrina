"""
Casbin Configuration Module

This module defines the configuration paths for the Casbin access control system, which is used to manage permissions
and enforce role-based access control (RBAC) in the application. Casbin is a powerful and flexible library that
supports various access control models including RBAC, ABAC (Attribute-Based Access Control), and more.

The paths defined here point to the model configuration file and the policy file, which together dictate how
permissions are evaluated and enforced. These files are critical for the correct functioning of the access
control system.

Attributes:
    MODEL_PATH (str): The absolute path to the Casbin model configuration file (model.conf). This file defines
the structure of access control rules, including request definitions, policy definitions, and matching logic.
    POLICY_PATH (str): The absolute path to the Casbin policy file (policy.csv). This file contains the specific
rules or policies that grant or deny access to resources based on roles or users.
"""

import os

# Define paths for Casbin model and policy files
MODEL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "model.conf")
POLICY_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "policy.csv") 