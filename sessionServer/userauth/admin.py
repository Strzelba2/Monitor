from django.contrib import admin
from django.contrib.auth import get_user_model
from django.urls import reverse
from django.utils.safestring import mark_safe
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.utils.translation import gettext_lazy as _

from .forms import UserChangeForm, UserCreationForm

User = get_user_model()


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    """
    Customizes the Django admin interface for the User model.

    Provides a user-friendly layout with links and organized field groups, allowing
    easier navigation and management of user records. This class configures forms,
    display options, and filtering/searching capabilities in the User admin section.
    """
    
    # Forms to use for adding and changing users in the admin interface
    form = UserChangeForm
    add_form = UserCreationForm
    
    # Fields to display in the list view
    list_display = [
        "email",
        "first_name",
        "last_name",
        "username_link",
        "is_superuser"
    ]
    
    list_display_links = ["email"]
    
    # Fields to allow search and filter options
    search_fields = ["email", "first_name", "last_name"]
    list_filter = ('is_staff', 'is_active')
    
    def username_link(self, obj) -> str:
        """
        Returns a clickable link for the username, pointing to the user's change page.

        Args:
            obj (User): The user object to retrieve the username link for.

        Returns:
            str: A safe HTML link to the user's admin change page, including a hash to 
            the "informacje-osobiste-tab" section of the page.
        """
        url = reverse(f"admin:{obj._meta.app_label}_{obj._meta.model_name}_change", args=[obj.pk]) + "#informacje-osobiste-tab"
        return mark_safe(f'<a href="{url}">{obj.username}</a>')
    
    username_link.short_description = "Username"
    username_link.allow_tags = True

    # Order users by email in the list view
    ordering = ["email"]
    
    # Define field grouping in the user detail view
    fieldsets = (
        (_("Login Credentials"), {"fields": ("email", "password")}),
        (_("Personal info"), {"fields": ("first_name", "last_name", "username")}),
        (
            _("Permissions and Groups"),
            {
                "fields": (
                    "is_active",
                    "is_staff",
                    "is_superuser",
                    "groups",
                    "user_permissions",
                )
            },
        ),
        (_("Important Dates"), {"fields": ("last_login", "date_joined")}),
    )
    
    # Field grouping in the user creation form
    add_fieldsets = (
        (
            None,
            {
                "classes": ("wide",),
                "fields": (
                    "username",
                    "email",
                    "first_name",
                    "last_name",
                    "password1",
                    "password2",
                ),
            },
        ),
    )
