"""Tests for Password Reset Email Service.

This module tests the password reset email functionality that was moved out of
the generic email service to maintain clean separation of concerns.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, Mock

from src.core.config.email import EmailSettings
from src.core.exceptions import EmailServiceError, TemplateRenderError
from src.domain.entities.user import User, Role
from src.domain.services.email.email_service import EmailService
from src.domain.services.forgot_password.password_reset_email_service import PasswordResetEmailService


class TestPasswordResetEmailService:
    """Test cases for PasswordResetEmailService."""
    
    @pytest.fixture
    def mock_email_service(self):
        """Mock EmailService."""
        mock = Mock(spec=EmailService)
        # Ensure render_template is not async
        mock.render_template = Mock(side_effect=[
            "<html>Default HTML</html>", 
            "Default text"
        ])
        mock.send_email = AsyncMock(return_value=True)
        return mock
    
    @pytest.fixture
    def email_settings(self):
        """Create email settings."""
        settings = EmailSettings()
        settings.PASSWORD_RESET_TOKEN_EXPIRE_MINUTES = 15
        settings.FROM_NAME = "Test App"
        settings.PASSWORD_RESET_URL_BASE = "https://example.com/reset-password"
        return settings
    
    @pytest.fixture
    def mock_user(self):
        """Create a test user entity."""
        user = User(
            id=1,
            username="testuser",
            email="test@example.com",
            hashed_password="hashed_password",
            role=Role.USER,
            is_active=True
        )
        return user
    
    @pytest.fixture
    def password_reset_email_service(self, mock_email_service, email_settings):
        """Create PasswordResetEmailService instance with mocked dependencies."""
        return PasswordResetEmailService(
            email_service=mock_email_service,
            settings=email_settings
        )
    
    def test_password_reset_email_service_initialization(self, mock_email_service, email_settings):
        """Test PasswordResetEmailService initialization with dependencies."""
        # Act
        service = PasswordResetEmailService(
            email_service=mock_email_service,
            settings=email_settings
        )
        
        # Assert
        assert service.email_service == mock_email_service
        assert service.settings == email_settings
    
    @pytest.mark.asyncio
    async def test_send_password_reset_email_success(
        self,
        password_reset_email_service,
        mock_email_service,
        mock_user
    ):
        """Test successful password reset email sending."""
        # Arrange
        token = "test_token_123"
        language = "en"

        mock_email_service.render_template.side_effect = [
            "<html>Reset email</html>",  # HTML template
            "Reset email text"           # Text template
        ]
        mock_email_service.send_email.return_value = True

        # Act
        result = await password_reset_email_service.send_password_reset_email(
            user=mock_user,
            token=token,
            language=language
        )

        # Assert
        assert result is True
        assert mock_email_service.render_template.call_count == 2
        mock_email_service.send_email.assert_called_once()

        # Verify email sending arguments
        send_call_args = mock_email_service.send_email.call_args
        assert send_call_args[1]['to_email'] == mock_user.email
        assert "Password Reset" in send_call_args[1]['subject']
        assert isinstance(send_call_args[1]['html_content'], str)
        assert isinstance(send_call_args[1]['text_content'], str)
        assert send_call_args[1]['html_content'] == "<html>Reset email</html>"
        assert send_call_args[1]['text_content'] == "Reset email text"
    
    @pytest.mark.asyncio
    async def test_send_password_reset_email_with_language_fallback(
        self,
        password_reset_email_service,
        mock_email_service,
        mock_user
    ):
        """Test password reset email with language fallback to English."""
        # Arrange
        token = "test_token_123"
        language = "fr"  # Unsupported language

        # Mock template rendering to succeed for English
        mock_email_service.render_template.side_effect = [
            "<html>Reset email in English</html>",
            "Reset email text in English"
        ]
        mock_email_service.send_email.return_value = True

        # Act
        result = await password_reset_email_service.send_password_reset_email(
            user=mock_user,
            token=token,
            language=language
        )

        # Assert
        assert result is True
        # Should call template rendering 2 times for English fallback
        assert mock_email_service.render_template.call_count == 2
        mock_email_service.send_email.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_send_password_reset_email_template_error(
        self,
        password_reset_email_service,
        mock_email_service,
        mock_user
    ):
        """Test password reset email when template rendering fails."""
        # Arrange
        token = "test_token_123"
        language = "en"

        # Make all template rendering fail (including fallbacks)
        mock_email_service.render_template.side_effect = TemplateRenderError("Template error")

        # Act & Assert
        with pytest.raises(EmailServiceError, match="Failed to render password reset email template"):
            await password_reset_email_service.send_password_reset_email(
                user=mock_user,
                token=token,
                language=language
            )
    
    @pytest.mark.asyncio
    async def test_send_password_reset_email_send_failure(
        self,
        password_reset_email_service,
        mock_email_service,
        mock_user
    ):
        """Test password reset email when email sending fails."""
        # Arrange
        token = "test_token_123"
        language = "en"
        
        mock_email_service.render_template.side_effect = [
            "<html>Reset email</html>",
            "Reset email text"
        ]
        mock_email_service.send_email.side_effect = Exception("SMTP Error")
        
        # Act & Assert
        with pytest.raises(EmailServiceError, match="Failed to send password reset email"):
            await password_reset_email_service.send_password_reset_email(
                user=mock_user,
                token=token,
                language=language
            )
    
    def test_build_reset_url(self, password_reset_email_service):
        """Test password reset URL building."""
        # Arrange
        token = "test_token_123"
        
        # Act
        result = password_reset_email_service._build_reset_url(token)
        
        # Assert
        assert result == "https://example.com/reset-password?token=test_token_123"
    
    @pytest.mark.asyncio
    async def test_send_password_reset_email_context_variables(
        self,
        password_reset_email_service,
        mock_email_service,
        mock_user,
        email_settings
    ):
        """Test that correct context variables are passed to templates."""
        # Arrange
        token = "test_token_123"
        language = "en"
        
        mock_email_service.render_template.side_effect = [
            "<html>Reset email</html>",
            "Reset email text"
        ]
        mock_email_service.send_email.return_value = True
        
        # Act
        await password_reset_email_service.send_password_reset_email(
            user=mock_user,
            token=token,
            language=language
        )
        
        # Assert
        # Check first template call (HTML)
        first_call = mock_email_service.render_template.call_args_list[0]
        context = first_call[1]
        
        assert context['user'] == mock_user
        assert context['token'] == token
        assert context['expire_minutes'] == email_settings.PASSWORD_RESET_TOKEN_EXPIRE_MINUTES
        assert context['app_name'] == email_settings.FROM_NAME
        assert context['language'] == language
        assert 'reset_url' in context
        assert token in context['reset_url'] 