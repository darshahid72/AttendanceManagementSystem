from django.conf import settings
from django.contrib.auth.models import AbstractUser
from django.db import models


class BaseUser(AbstractUser):
    """
    Custom user model that inherits AbstractUser and adds additional fields.
    """
    ROLE_CHOICES = [
        ('manager', 'Manager'),
        ('staff', 'Staff'),
    ]
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default='staff')
    user_code = models.CharField(max_length=255, default=settings.DEFAULT_USER_CODE)
    mobile = models.CharField(max_length=20, null=True, blank=True)
    designation = models.CharField(max_length=50, null=True, blank=True)
    
    # Provide unique related_name for groups and user_permissions
    groups = models.ManyToManyField(
        'auth.Group',
        verbose_name='groups',
        blank=True,
        related_name='user_groups'  # Changed related_name to avoid clash
    )
    user_permissions = models.ManyToManyField(
        'auth.Permission',
        verbose_name='user permissions',
        blank=True,
        related_name='user_permissions_set'  # Changed related_name to avoid clash
    )
    
    class Meta:
        db_table = 'base_user'

    def save(self, *args, **kwargs):
        super(BaseUser, self).save(*args, **kwargs)
