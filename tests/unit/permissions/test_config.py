"""
Unit Tests for Casbin Configuration

This module contains unit tests for the Casbin configuration settings defined in src/permissions/config.py.
It ensures that the paths to the model and policy files are correctly set and point to existing files, which is
critical for the proper initialization of the Casbin enforcer.

Tests:
    - test_model_path_exists: Verifies that the model configuration file path exists and is a file.
    - test_policy_path_exists: Verifies that the policy file path exists and is a file.
    - test_paths_are_absolute: Confirms that the paths are absolute to avoid issues with relative path resolution.
"""

import os
import pytest
from src.permissions.config import MODEL_PATH, POLICY_PATH

def test_model_path_exists():
    """
    Test that the Casbin model configuration file path exists and is a file.

    This test ensures that MODEL_PATH points to an existing file, which is necessary for the Casbin enforcer to
    load the access control model definition. If the file does not exist, the enforcer initialization will fail.

    Asserts:
        - MODEL_PATH exists as a file in the filesystem.
    """
    assert os.path.isfile(MODEL_PATH), f"Model configuration file does not exist at {MODEL_PATH}"

def test_policy_path_exists():
    """
    Test that the Casbin policy file path exists and is a file.

    This test ensures that POLICY_PATH points to an existing file, which contains the specific access control
    policies used by the Casbin enforcer. If the file is missing, no policies will be loaded, potentially leading
    to incorrect permission decisions (e.g., denying all access).

    Asserts:
        - POLICY_PATH exists as a file in the filesystem.
    """
    assert os.path.isfile(POLICY_PATH), f"Policy file does not exist at {POLICY_PATH}"

def test_paths_are_absolute():
    """
    Test that the Casbin model and policy paths are absolute.

    This test verifies that both MODEL_PATH and POLICY_PATH are absolute paths to prevent issues related to
    relative path resolution, which could vary depending on the working directory from which the application is
    run. Absolute paths ensure consistent behavior across different environments.

    Asserts:
        - MODEL_PATH is an absolute path.
        - POLICY_PATH is an absolute path.
    """
    assert os.path.isabs(MODEL_PATH), f"Model path {MODEL_PATH} is not absolute"
    assert os.path.isabs(POLICY_PATH), f"Policy path {POLICY_PATH} is not absolute" 