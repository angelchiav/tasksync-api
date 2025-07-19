from django.db import models
from django.contrib.auth.models import AbstractUser
from django.core.validators import MinValueValidator, MaxValueValidator
from datetime import datetime, timedelta
from django.utils import timezone

# Añadir métodos para manejo de modelos
# Organizar mejor la estructura y analizar qué agregar a admin
# Añadir o no datos físicos (país, ciudad, etc.) (? )

class User(AbstractUser):
    """
    Extended user model with sync and notification preferences.
    """
    # Email frequency choices
    EMAIL_FREQUENCY_CHOICES = [
        ('immediate', 'Immediate'),
        ('hourly', 'Hourly Digest'),
        ('daily', 'Daily Digest'),
        ('weekly', 'Weekly Digest'),
        ('disabled', 'Disabled')
    ]

    email = models.EmailField(
        "Email address",
        unique=True,
        help_text="Email address for login and notifications"
    )

    timezone = models.CharField(
        "Timezone",
        max_length=50, 
        default='UTC',
    )

    sync_frequency = models.IntegerField(
        "Sync Frequency (in minutes)",
        max_length=60,
        validators=[MinValueValidator(5), MaxValueValidator(1440)],
        help_text="How often to sync tasks (5-1440 minutes)."
    )

    notification_preferences = models.JSONField(
        "Notification Preferences",
        default=dict,
        blank=True,
        help_text="User notification preferences stored as JSON"
    )

    is_sync_enabled = models.BooleanField(
        "Sync Enabled",
        default=True,
        help_text="Enable/disable automatic synchronization"
    )

    last_sync_at = models.DateTimeField(
        "Last Sync",
        blank=True,
        null=True,
        help_text="Timestamp of last successfull sync"
    )


    # Notification preferences


    profile_picture = models.ImageField(
        "Profile picture",
        upload_to="profile_pictures/%Y/%m",
        blank=True,
        null=True
    )

    is_email_verified = models.BooleanField(
        "Email verified",
        default=False,
        help_text="Whether user's email is verified"
    )

    email_verification_token = models.CharField(
        "Email Verification Token",
        max_length=64,
        null=True,
        blank=True
    )

    last_login_ip = models.GenericIPAddressField(
        "Last Login IP",
        blank=True,
        null=True
    )

    failed_login_attempts = models.IntegerField(
        "Failed Login Attempts",
        default=0
    )

    account_locked_until = models.DateTimeField(
        "Account Locked Until",
        null=True,
        blank=True
    )

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    class Meta:
        verbose_name = 'User'
        verbose_name_plural = 'Users'
    
    def __str__(self) -> str:
        return f"{self.email} ({self.get_full_name() or self.username})"
    
class ExternalAccount(models.Model):
    """
    External service accounts connected to the user (Google, Notion, Todoist)
    """
    PROVIDER_CHOICES = [
        ('google', 'Google Tasks'),
        ('notion', 'Notion'),
        ('todoist', 'Todoist')
    ]

    # Relationships
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="external_accounts",
        help_text="User who owns this external account"
    )

    provider = models.CharField(
        "Provider",
        max_length=50,
        choices=PROVIDER_CHOICES,
        help_text="External service provider"
    )

    provider_user_id = models.CharField(
        "Provider User ID",
        max_length=255,
        help_text="User ID in the external provider"
    )

    email = models.EmailField(
        "Provider Email",
        help_text="Email address used with provider"
    )

    display_name = models.CharField(
        "Display Name",
        max_length=255,
        help_text="Display name from the provider"
    )

    # OAuth2 tokens (encrypted)
    access_token = models.TextField(
        "Access Token",
        help_text="Encrypted OAuth2 access token"
    )

    refresh_token = models.TextField(
        "Refresh Token",
        blank=True,
        null=True,
        help_text="Encrypted OAuth2 refresh token"
    )

    token_expires_at = models.DateTimeField(
        "Token Expires At",
        blank=True,
        null=True,
        help_text="When the access token expires"
    )

    # Account status
    is_active = models.BooleanField(
        "Active",
        default=True,
        help_text="Whether this account connection is active"
    )

    sync_enabled = models.BooleanField(
        "Sync Enabled",
        default=True,
        help_text="Whether to sync data from this account"
    )

    last_sync_at = models.DateTimeField(
        "Last Sync",
        blank=True,
        null=True,
        help_text="Last successful sync with this provider"
    )

    # OAuth2 scopes
    scopes = models.JSONField(
        "OAuth Scopes",
        default=list,
        help_text="OAuth2 scopes granted by the user"
    )

    connection_errors = models.IntegerField(
        "Connection Errors",
        default=0,
        help_text="Number of consecutive connection errors"
    )

    last_error = models.TextField(
        "Last Error",
        blank=True,
        help_text="Last connection or sync error message"
    )

    last_error_at = models.DateTimeField(
        "Last Error At",
        blank=True,
        null=True
    )

    class Meta:
        verbose_name = "External Account"
        verbose_name_plural = "External Accounts"
        unique_together = [
            ('user', 'provider', 'provider_user_id')
        ]
    
    def __str__(self) -> str:
        return f"{self.user.email}"
    
class OAuthState(models.Model):
    """
    OAuth2 state management for secure authorization flows.
    """
    state = models.CharField(
        "State",
        max_length=64,
        unique=True,
        help_text="OAuth2 state parameter"
    )

    # Associated user
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="oauth_states",
        help_text="User initiating OAuth flow"
    )

    # Provider info
    provider = models.CharField(
        "Provider",
        max_length=50,
        choices=ExternalAccount.PROVIDER_CHOICES,
        help_text="OAuth provider"
    )

    # OAuth parameters
    redirect_uri = models.URLField(
        "Redirect URI",
        help_text="OAuth2 redirect URI"
    )

    # Permissions(?
    scopes = models.JSONField(
        "Scopes",
        default=list,
        help_text="Requested OAuth2 scopes"
    )

    # PROOF KEY FOR CODE EXCHANGE PARAMETERS (PKCE)

    code_verifier = models.CharField(
        "Code Verifier",
        max_length=128,
        blank=True,
        help_text="PKCE code verifier"
    )

    code_challenge = models.CharField(
        "Code Challenge",
        max_length=128,
        blank=True,
        help_text="PKCE code challenge"
    )

    # State management
    expires_at = models.DateTimeField(
        "Expires At",
        default=lambda: timezone.now() + timedelta(minutes=10),
        help_text="When this state expires"
    )

    is_used = models.BooleanField(
        "Used",
        default=False,
        help_text="Whether this state is has been used"
    )

    # Request metadata
    user_agent = models.TextField(
        "User Agent",
        blank=True,
        help_text="User agent of the request"
    )

    ip_address = models.GenericIPAddressField(
        "IP Address",
        blank=True,
        null=True,
        help_text="IP Address of the request"
    )

    class Meta:
        verbose_name = "OAuth State"
        verbose_name_plural = "OAuth States"
    
    def __str__(self) -> str:
        return f"{self.user.email} - {self.provider} - {self.state[:8]}"

class UserSession(models.Model):
    """
    Track user sessions for security and analytics
    """
    # Session info
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="sessions"
    )

    session_key = models.CharField(
        "Session Key",
        max_length=40,
        unique=True
    )

    # Device/browser info (maybe not necessary)...
    ip_address = models.GenericIPAddressField(
        "IP Address"
    )

    user_agent = models.TextField(
        "User Agent",
        blank=True
    )

    device_type = models.CharField(
        "Device Type",
        max_length=20,
        choices=[
            ('desktop', 'Desktop'),
            ('mobile', 'Mobile'),
            ('tablet', 'Tablet'),
            ('unknown', 'Unknown')
        ],
        default='unknown'
    )

    is_active = models.BooleanField(
        "Active",
        default=True
    )

    last_activity = models.DateTimeField(
        "Last Activity",
        auto_now=True
    )

    expires_at = models.DateTimeField(
        "Expires At"
    )

    class Meta:
        verbose_name = "User Session"
        verbose_name_plural = "User Sessions"

    def __str__(self) -> str:
        return f"{self.user.email} - {self.ip_address}"