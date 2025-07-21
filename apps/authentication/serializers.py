from rest_framework import serializers
from django.contrib.auth import authenticate, password_validation
from django.contrib.auth.password_validation import validate_password
from django.conf import settings
from django.utils import timezone
from datetime import timedelta
import secrets
import hashlib
import base64
from .models import User, ExternalAccount, OAuthState, UserSession

class UserProfileSerializer(serializers.ModelSerializer):
    """
    Complete user profile serializer with all fields and computed properties
    """
    full_name = serializers.SerializerMethodField()
    connected_providers = serializers.SerializerMethodField()
    sync_enabled_providers = serializers.SerializerMethodField()
    next_sync_at = serializers.SerializerMethodField()
    account_status = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = [
            # Basic info
            'id', 'username', 'email', 'first_name', 'last_name', 'full_name',
            
            # Profile
            'profile_picture', 'timezone',

            # Sync Settings
            'sync_frequency', 'is_sync_enabled', 'last_sync_at', 'next_sync_at',

            # Notification Preferences
            'notification_preferences',

            # Account Status
            'is_email_verified', 'account_status',

            # Connections
            'connected_providers', 'sync_enabled_providers',

            # TimeStamps
            'date_joined', 'last_login'
        ]
        read_only_fields = [
            'id',
            'date_joined',
            'last_login',
            'last_sync_at',
            'full_name',
            'connected_providers',
            'sync_enabled_providers',
            'next_sync_at',
            'account_status'
        ]
        extra_kwargs = {
            'email': {'required': True},
            'sync_frequency': {'min_value': 5, 'max_value': 1440}
        }

        def get_full_name(self, obj):
            """Get user's full name or fallback to username"""
            full_name = obj.get_full_name()
            return full_name if full_name.strip() else obj.username
        
        def get_connected_providers(self, obj):
            """Get list of connected external providers"""
            return obj.connected_providers
        
        def get_sync_enabled_providers(self, obj):
            """Get list of providers with sync enabled"""
            return obj.sync_enabled_providers
        
        def get_next_sync_at(self, obj):
            """Calculate when the next sync should occur"""
            if not obj.is_sync_enabled or not obj.last_sync_at:
                return None
            
            next_sync = obj.last_sync_at + timedelta(minutes=obj.sync_frequency)
            return next_sync if next_sync > timezone.now() else timezone.now()

        def get_account_status(self, obj):
            """Get comprehensive account status"""
            status = {
                'is_active': obj.is_active,
                'is_email_verified': obj.is_email_verified,
                'is_locked': obj.is_account_locked(),
                'failed_login_attempts': obj.failed_login_attempts,
                'has_connected_accounts': obj.external_accounts.filter(is_active=True).exists(),
                'sync_status': 'enabled' if obj.is_sync_enabled else 'disabled'
            }
            return status
        
        def validate_email(self, value):
            """Validate email uniqueness"""
            user = User.objects.filter(email=value)
            if user.exclude(pk=user.pk if user else None).exists():
                raise serializers.ValidationError("An user with this email already exists")
            return value
        
        def validate_timezone(self, value):
            """Validate timezone string."""
            import pytz
            try:
                pytz.timezone(value)
            except pytz.UnknownTimeZoneError:
                raise serializers.ValidationError("Invalid timezone")
            return value
        
        def update(self, instance, validated_data):
            """Custom update to handle notification preferences"""
            notification_prefs = validated_data.get('notification_preferences')
            if notification_prefs:
                # Merge with existing preferences
                current_prefs = instance.notification_preferences or {}
                current_prefs.update(notification_prefs)
                validated_data['notification_preferences'] = current_prefs

            return super().update(instance, validated_data)

class UserRegistrationSerializer(serializers.ModelSerializer):
    """
    User Registration with Password Validation
    """
    password = serializers.CharField(write_only=True, style={'input_type': 'password'})
    password2 = serializers.CharField(write_only=True, style={'input_type': 'password'})

    class Meta:
        model = User
        fields = [
            'username', 'email', 'first_name', 'last_name',
            'password', 'password2', 'timezone'
        ]
        extra_kwargs = {
            'email': {'required': True},
            'first_name': {'required': True},
            'last_name': {'required': True}
        }
    def validate(self, attrs):
        """Validate password and strength"""
        password = attrs.get('password')
        password2 = attrs.pop('password2', None)

        if password != password2:
            raise serializers.ValidationError({
                'error': 'Passwords do not match'
        })

        try:
            password_validation.validate_password(password)
        
        except Exception as e:
            raise serializers.ValidationError({
                'error': e
            })
        
        return attrs
    
    def create(self, validated_data):
        """User creation with encrypted password"""
        password = validated_data.pop('password')
        user = User(**validated_data)
        user.set_password(password) # Encrypted password
        user.save()
        return user
    
class UserPasswordChangeSerializer(serializers.Serializer):
    """
    Password change with validation
    """
    current_password = serializers.CharField(
        write_only=True, 
        style={'input_type': 'password'}
    )
    new_password = serializers.CharField(
        write_only=True, 
        style={'input_type': 'password'}
    )
    new_password_confirm = serializers.CharField(
        write_only=True, 
        style={'input_type': 'password'}
    )

    def validate_current_password(self, value):
        """Validate current password"""
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError("Current password is incorrect")
        return value
    
    def validate(self, attrs):
        """Validate new password confirmation and strength"""
        new_password = attrs.get('new_password')
        new_password_confirm = attrs.get('new_password_confirm')
        
        if new_password != new_password_confirm:
            raise serializers.ValidationError({
                'error': 'New passwords do not match'
            })
        
        try:
            validate_password(new_password, self.context['request'].user)
        except Exception as e:
            raise serializers.ValidationError({
                'new_password': e
            })
        return attrs
    
    def save(self):
        """Update new password"""
        user = self.context['request'].user
        user.set_password(self.validated_data['new_password'])
        user.save()
        return user
    
class OAuthUrlSerializer(serializers.Serializer):
    """
    Serializer for generating OAuth authorization URLs
    """
    provider = serializers.ChoiceField(choices=ExternalAccount.PROVIDER_CHOICES)
    redirect_uri = serializers.URLField()

    def validate_provider(self, value):
        """Validate provider configuration exists"""
        if value not in settings.OAUTH2_PROVIDERS:
            raise serializers.ValidationError(f"Provider '{value}' is not configured")
        return value
    
    def validate_redirect_uri(self, value):
        """Redirect URI is allowed"""
        allowed_uris = getattr(settings, 'ALLOWED_OAUTH_REDIRECT_URIS', [])
        if allowed_uris and value not in allowed_uris:
            raise serializers.ValidationError("Redirect URI not allowed")
        return value
    
class OAuthCallbackSerializer(serializers.Serializer):
    """
    Serializer for handling OAuth2 callbacks
    """
    provider = serializers.ChoiceField(choices=ExternalAccount.PROVIDER_CHOICES)
    code = serializers.CharField()
    state = serializers.CharField()
    error = serializers.CharField(required=False)
    error_description = serializers.CharField(required=False)
    
    def validate(self, attrs):
        """Validate OAuth callbacks parameters"""
        if attrs.get('error'):
            error_msg = attrs.get('error_description', attrs['error'])
            raise serializers.ValidationError({"OAuth error": {error_msg}})
        
        if not attrs.get('code'):
            raise serializers.ValidationError("Authorization code is required")
        
        return attrs
    
class OAuthStateSerializer(serializers.ModelSerializer):
    """
    OAuth state serializer for debugging (development only) ELIMINAR PARA PRODUCCIÓN
    """
    is_expired = serializers.SerializerMethodField()
    is_valid = serializers.SerializerMethodField()

    class Meta:
        model = OAuthState
        fields = [
            'id', 'state', 'user', 'provider', 'redirect_uri',
            'scopes', 'expires_at', 'is_used', 'is_expired',
            'is_valid', 'user_agent', 'ip_address', 'created_at'
        ]
        read_only_fields = ['id', 'created_at']

    def get_is_expired(self, obj):
        """If OAuth state is expired"""
        return obj.is_expired()
    
    def get_is_valid(self, obj):
        """If OAuth state is valid to use"""
        return obj.is_valid()
    
