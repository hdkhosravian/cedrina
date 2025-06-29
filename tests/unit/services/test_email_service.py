"""Tests for Email Service functionality.

This module tests the email service domain logic including template rendering,
secure email sending, and forgot password email functionality following TDD principles.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from pathlib import Path
from jinja2 import Template, DictLoader

from src.domain.entities.user import User, Role
from src.domain.services.email.email_service import EmailService
from src.core.exceptions import EmailServiceError, TemplateRenderError
from src.core.config.email import EmailSettings


class TestEmailService:
    """Test cases for EmailService domain service."""
    
    @pytest.fixture
    def email_settings(self):
        """Create test email settings."""
        return EmailSettings(
            EMAIL_TEST_MODE=True,
            SMTP_HOST="localhost",
            SMTP_PORT=587,
            SMTP_USERNAME="test",
            SMTP_PASSWORD="password",
            FROM_EMAIL="test@example.com",
            FROM_NAME="Test App",
            EMAIL_TEMPLATES_DIR="tests/fixtures/email_templates",
            PASSWORD_RESET_TOKEN_EXPIRE_MINUTES=15,
            PASSWORD_RESET_URL_BASE="http://localhost:3000/reset-password"
        )
    
    @pytest.fixture
    def mock_user(self):
        """Create a test user entity."""
        return User(
            id=1,
            username="testuser",
            email="user@example.com",
            hashed_password="hashed_password",
            role=Role.USER,
            is_active=True
        )
    
    @pytest.fixture
    def email_service(self, email_settings):
        """Create EmailService instance with test settings."""
        return EmailService(email_settings)
    
    def test_email_service_initialization(self, email_settings):
        """Test EmailService initialization with settings."""
        # Act
        service = EmailService(email_settings)
        
        # Assert
        assert service.settings == email_settings
        assert service.jinja_env is not None
        assert hasattr(service, 'fastmail')
    
    def test_email_service_template_loading(self, email_service):
        """Test that email service can load and configure Jinja2 templates."""
        # Act
        template = email_service.jinja_env.from_string("Hello {{ name }}!")
        result = template.render(name="World")
        
        # Assert
        assert result == "Hello World!"
    
    def test_render_template_success(self, email_service):
        """Test successful template rendering with variables."""
        # Arrange
        template_content = """
        Hello {{ user.username }}!
        
        Click here to reset your password:
        {{ reset_url }}
        
        This link expires in {{ expire_minutes }} minutes.
        """
        
        # Mock the jinja environment to use DictLoader with our template
        mock_template = Template(template_content)
        
        with patch.object(email_service.jinja_env, 'get_template') as mock_get_template:
            mock_get_template.return_value = mock_template
            
            with patch('src.domain.services.email.email_service.Path.exists', return_value=True):
                # Act
                result = email_service.render_template(
                    'test_template.html',
                    user=User(username="testuser", email="test@example.com"),
                    reset_url="http://example.com/reset",
                    expire_minutes=15
                )
        
        # Assert
        assert "Hello testuser!" in result
        assert "http://example.com/reset" in result
        assert "15 minutes" in result
    
    @patch('src.domain.services.email.email_service.Path.exists')
    def test_render_template_file_not_found(self, mock_path_exists, email_service):
        """Test template rendering when template file doesn't exist."""
        # Arrange
        mock_path_exists.return_value = False
        
        # Act & Assert
        with pytest.raises(TemplateRenderError, match="Template file not found"):
            email_service.render_template('nonexistent.html', name="test")
    
    def test_render_template_jinja_error(self, email_service):
        """Test template rendering with Jinja2 template errors."""
        # Arrange
        template_content = "Hello {{ undefined_variable.missing_attr }}!"
        mock_template = Template(template_content)
        
        with patch.object(email_service.jinja_env, 'get_template') as mock_get_template:
            mock_get_template.return_value = mock_template
            
            with patch('src.domain.services.email.email_service.Path.exists', return_value=True):
                # Act & Assert
                with pytest.raises(TemplateRenderError, match="Template rendering failed"):
                    email_service.render_template('bad_template.html')
    
    @pytest.mark.asyncio
    async def test_send_email_success_test_mode(self, email_service, mock_user):
        """Test successful email sending in test mode."""
        # Arrange
        email_service.settings.EMAIL_TEST_MODE = True
        
        # Act
        result = await email_service.send_email(
            to_email=mock_user.email,
            subject="Test Subject",
            html_content="<h1>Test Content</h1>",
            text_content="Test Content"
        )
        
        # Assert
        assert result is True
    
    @pytest.mark.asyncio
    async def test_send_email_success_production_mode(self, email_service, mock_user):
        """Test successful email sending in production mode."""
        # Arrange
        email_service.settings.EMAIL_TEST_MODE = False
        mock_fastmail = AsyncMock()
        email_service.fastmail = mock_fastmail
        
        # Act
        result = await email_service.send_email(
            to_email=mock_user.email,
            subject="Test Subject",
            html_content="<h1>Test Content</h1>",
            text_content="Test Content"
        )
        
        # Assert
        assert result is True
        mock_fastmail.send_message.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_send_email_failure_production_mode(self, email_service, mock_user):
        """Test email sending failure in production mode."""
        # Arrange
        email_service.settings.EMAIL_TEST_MODE = False
        mock_fastmail = AsyncMock()
        mock_fastmail.send_message.side_effect = Exception("SMTP Error")
        email_service.fastmail = mock_fastmail
        
        # Act & Assert
        with pytest.raises(EmailServiceError, match="Failed to send email"):
            await email_service.send_email(
                to_email=mock_user.email,
                subject="Test Subject",
                html_content="<h1>Test Content</h1>",
                text_content="Test Content"
            )
    
    @pytest.mark.asyncio
    async def test_send_email_production_mode(self, email_service):
        """Test email sending in production mode fails when FastMail not configured."""
        # Arrange
        email_service.settings.EMAIL_TEST_MODE = False
        to_email = "test@example.com"
        subject = "Test Subject"
        html_content = "<h1>Test</h1>"
        text_content = "Test"

        # Act & Assert
        with pytest.raises(EmailServiceError, match="Failed to send email"):
            await email_service.send_email(
                to_email=to_email,
                subject=subject,
                html_content=html_content,
                text_content=text_content
            )
    
    def test_email_template_security_html_escaping(self, email_service):
        """Test that email templates properly escape HTML to prevent injection."""
        # Arrange
        malicious_content = "<script>alert('xss')</script>"
        template_content = "Hello {{ username }}!"
        
        # Use the environment's from_string method to preserve auto-escaping
        mock_template = email_service.jinja_env.from_string(template_content)
        
        with patch.object(email_service.jinja_env, 'get_template') as mock_get_template:
            mock_get_template.return_value = mock_template
            
            with patch('src.domain.services.email.email_service.Path.exists', return_value=True):
                # Act
                result = email_service.render_template('test.html', username=malicious_content)
        
        # Assert
        # Jinja2 auto-escapes by default, so script tags should be escaped
        assert "&lt;script&gt;" in result and malicious_content not in result
    
    def test_email_service_configuration_validation(self, email_settings):
        """Test that email service validates configuration properly."""
        # Test that invalid configuration raises validation error
        with pytest.raises(Exception):  # Pydantic ValidationError
            invalid_settings = EmailSettings(
                EMAIL_TEST_MODE=False,
                SMTP_HOST="",  # Invalid empty host
                FROM_EMAIL="invalid-email"  # Invalid email format
            )
        
        # Test that valid configuration works
        valid_service = EmailService(email_settings)
        assert valid_service.settings == email_settings 