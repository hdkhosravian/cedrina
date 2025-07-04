"""Unit tests for token management service interfaces.

This module tests the token management service interfaces to ensure they follow
Domain-Driven Design principles and provide the correct contracts for JWT token
and session management operations.

Test Coverage:
- Interface method signatures and documentation
- DDD principles compliance
- Single responsibility validation
- Ubiquitous language verification
- Security considerations validation
"""

import pytest
from abc import ABC
from typing import Optional, Tuple

from src.domain.entities.user import User
from src.domain.entities.session import Session
from src.domain.interfaces.token_management import ITokenService, ISessionService
from src.domain.value_objects.jwt_token import AccessToken, RefreshToken


class TestTokenManagementInterfaces:
    """Test token management service interfaces for DDD compliance."""

    def test_token_service_interface_design(self):
        """Test ITokenService interface design and DDD compliance."""
        # Verify interface inheritance
        assert issubclass(ITokenService, ABC)
        
        # Verify interface has abstract methods
        assert hasattr(ITokenService, '__abstractmethods__')
        abstract_methods = ITokenService.__abstractmethods__
        
        # Verify required methods exist
        expected_methods = {
            'create_access_token',
            'create_refresh_token',
            'refresh_tokens',
            'validate_access_token',
            'revoke_refresh_token',
            'revoke_access_token',
            'validate_token'
        }
        assert all(method in abstract_methods for method in expected_methods)
        
        # Verify method signatures
        import inspect
        
        # Check create_access_token signature
        sig = inspect.signature(ITokenService.create_access_token)
        params = list(sig.parameters.keys())
        assert 'self' in params
        assert 'user' in params
        assert sig.return_annotation == AccessToken
        
        # Check create_refresh_token signature
        sig = inspect.signature(ITokenService.create_refresh_token)
        params = list(sig.parameters.keys())
        assert 'self' in params
        assert 'user' in params
        assert 'jti' in params
        assert sig.parameters['jti'].annotation == Optional[str]
        assert sig.return_annotation == RefreshToken
        
        # Check refresh_tokens signature
        sig = inspect.signature(ITokenService.refresh_tokens)
        params = list(sig.parameters.keys())
        assert 'self' in params
        assert 'refresh_token' in params
        assert sig.return_annotation == Tuple[AccessToken, RefreshToken]

    def test_session_service_interface_design(self):
        """Test ISessionService interface design and DDD compliance."""
        # Verify interface inheritance
        assert issubclass(ISessionService, ABC)
        
        # Verify interface has abstract methods
        assert hasattr(ISessionService, '__abstractmethods__')
        abstract_methods = ISessionService.__abstractmethods__
        
        # Verify required methods exist
        expected_methods = {
            'create_session',
            'get_session',
            'revoke_session',
            'is_session_valid',
            'update_session_activity'
        }
        assert all(method in abstract_methods for method in expected_methods)
        
        # Verify method signatures
        import inspect
        
        # Check create_session signature
        sig = inspect.signature(ISessionService.create_session)
        params = list(sig.parameters.keys())
        assert 'self' in params
        assert 'user_id' in params
        assert 'jti' in params
        assert 'refresh_token_hash' in params
        assert 'expires_at' in params
        assert sig.return_annotation is None
        
        # Check get_session signature
        sig = inspect.signature(ISessionService.get_session)
        params = list(sig.parameters.keys())
        assert 'self' in params
        assert 'jti' in params
        assert 'user_id' in params
        assert sig.return_annotation == Optional[Session]

    def test_interfaces_follow_single_responsibility_principle(self):
        """Test that each interface follows the Single Responsibility Principle."""
        # ITokenService - only JWT token operations
        token_methods = ITokenService.__abstractmethods__
        assert len(token_methods) == 7  # All token-related methods
        assert all('token' in method or 'access' in method or 'refresh' in method 
                  for method in token_methods)
        
        # ISessionService - only session state management
        session_methods = ISessionService.__abstractmethods__
        assert len(session_methods) == 5  # All session-related methods
        assert all('session' in method for method in session_methods)

    def test_interfaces_use_ubiquitous_language(self):
        """Test that interfaces use ubiquitous language from the business domain."""
        # Method names should reflect business concepts, not technical concepts
        
        # Token domain language
        assert 'create_access_token' in ITokenService.__abstractmethods__
        assert 'create_refresh_token' in ITokenService.__abstractmethods__
        assert 'refresh_tokens' in ITokenService.__abstractmethods__
        assert 'validate_access_token' in ITokenService.__abstractmethods__
        assert 'revoke_refresh_token' in ITokenService.__abstractmethods__
        assert 'revoke_access_token' in ITokenService.__abstractmethods__
        
        # Session domain language
        assert 'create_session' in ISessionService.__abstractmethods__
        assert 'get_session' in ISessionService.__abstractmethods__
        assert 'revoke_session' in ISessionService.__abstractmethods__
        assert 'is_session_valid' in ISessionService.__abstractmethods__
        assert 'update_session_activity' in ISessionService.__abstractmethods__

    def test_interfaces_use_domain_value_objects(self):
        """Test that interfaces use domain value objects for type safety."""
        # Verify that interfaces use domain value objects instead of primitives
        
        import inspect
        
        # ITokenService should use AccessToken and RefreshToken value objects
        sig = inspect.signature(ITokenService.create_access_token)
        assert sig.return_annotation == AccessToken
        
        sig = inspect.signature(ITokenService.create_refresh_token)
        assert sig.return_annotation == RefreshToken
        
        sig = inspect.signature(ITokenService.refresh_tokens)
        assert sig.return_annotation == Tuple[AccessToken, RefreshToken]

    def test_interfaces_include_security_considerations(self):
        """Test that interfaces include security considerations."""
        # All token and session interfaces should include security-related methods
        
        # ITokenService security methods
        assert 'revoke_refresh_token' in ITokenService.__abstractmethods__
        assert 'revoke_access_token' in ITokenService.__abstractmethods__
        assert 'validate_access_token' in ITokenService.__abstractmethods__
        assert 'validate_token' in ITokenService.__abstractmethods__
        
        # ISessionService security methods
        assert 'revoke_session' in ISessionService.__abstractmethods__
        assert 'is_session_valid' in ISessionService.__abstractmethods__
        assert 'update_session_activity' in ISessionService.__abstractmethods__

    def test_interfaces_include_i18n_support(self):
        """Test that interfaces include internationalization support."""
        # Token revocation methods should include language parameter for i18n
        
        import inspect
        
        # ITokenService
        sig = inspect.signature(ITokenService.revoke_refresh_token)
        assert 'language' in sig.parameters
        
        sig = inspect.signature(ITokenService.validate_token)
        assert 'language' in sig.parameters

    def test_interface_documentation_quality(self):
        """Test that interfaces have comprehensive documentation."""
        # Verify that all interfaces have proper docstrings
        
        assert ITokenService.__doc__ is not None
        assert "jwt" in ITokenService.__doc__.lower()
        assert "token" in ITokenService.__doc__.lower()
        assert "ddd" in ITokenService.__doc__.lower()
        
        assert ISessionService.__doc__ is not None
        assert "session" in ISessionService.__doc__.lower()
        assert "ddd" in ISessionService.__doc__.lower()

    def test_method_documentation_quality(self):
        """Test that interface methods have comprehensive documentation."""
        # Verify that all abstract methods have proper docstrings
        
        # ITokenService methods
        assert ITokenService.create_access_token.__doc__ is not None
        assert "creates" in ITokenService.create_access_token.__doc__.lower()
        
        assert ITokenService.create_refresh_token.__doc__ is not None
        assert "creates" in ITokenService.create_refresh_token.__doc__.lower()
        
        assert ITokenService.refresh_tokens.__doc__ is not None
        assert "refreshes" in ITokenService.refresh_tokens.__doc__.lower()
        
        assert ITokenService.revoke_refresh_token.__doc__ is not None
        assert "revokes" in ITokenService.revoke_refresh_token.__doc__.lower()
        
        # ISessionService methods
        assert ISessionService.create_session.__doc__ is not None
        assert "creates" in ISessionService.create_session.__doc__.lower()
        
        assert ISessionService.revoke_session.__doc__ is not None
        assert "revokes" in ISessionService.revoke_session.__doc__.lower()

    def test_interfaces_handle_optional_parameters_correctly(self):
        """Test that interfaces handle optional parameters correctly."""
        import inspect
        
        # ITokenService.create_refresh_token should have optional jti parameter
        sig = inspect.signature(ITokenService.create_refresh_token)
        jti_param = sig.parameters['jti']
        assert jti_param.annotation == Optional[str]
        assert jti_param.default is None
        
        # ITokenService.revoke_access_token should have optional expires_in parameter
        sig = inspect.signature(ITokenService.revoke_access_token)
        expires_param = sig.parameters['expires_in']
        assert expires_param.annotation == Optional[int]
        assert expires_param.default is None

    def test_interfaces_return_appropriate_types(self):
        """Test that interfaces return appropriate types for their operations."""
        import inspect
        
        # Creation methods should return the created objects
        sig = inspect.signature(ITokenService.create_access_token)
        assert sig.return_annotation == AccessToken
        
        sig = inspect.signature(ITokenService.create_refresh_token)
        assert sig.return_annotation == RefreshToken
        
        # Validation methods should return boolean or dict
        sig = inspect.signature(ISessionService.is_session_valid)
        assert sig.return_annotation == bool
        
        sig = inspect.signature(ITokenService.validate_access_token)
        assert sig.return_annotation == dict
        
        # Void methods should return None
        sig = inspect.signature(ITokenService.revoke_refresh_token)
        assert sig.return_annotation is None
        
        sig = inspect.signature(ISessionService.create_session)
        assert sig.return_annotation is None

        sig = inspect.signature(ISessionService.revoke_session)
        assert sig.return_annotation is None 