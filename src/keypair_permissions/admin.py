from django.contrib import admin
from .models import PublicKey


@admin.register(PublicKey)
class PublicKeyAdmin(admin.ModelAdmin):
    """Admin representation of PublicKey."""

    model = PublicKey

    list_display = ('public_key_id', 'signing_algorithm', 'hashing_algorithm', 'is_active', 'public_key', 'created_at')
    ordering = ('public_key_id', 'signing_algorithm', 'hashing_algorithm', '-created_at', 'public_key', 'is_active')
    list_filter = ('signing_algorithm', 'hashing_algorithm', 'created_at', 'is_active')
    search_fields = ('public_key_id', 'signing_algorithm', 'hashing_algorithm', 'public_key')
