from django.contrib import admin
from django.contrib.auth import get_user_model
from django.urls import reverse
from django.utils.safestring import mark_safe
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.utils.translation import gettext_lazy as _
from .models import UsedToken
from .forms import UserChangeForm, UserCreationForm

from django.core.signing import TimestampSigner
from django.utils.http import urlencode
from django.utils.html import format_html

User = get_user_model()

admin.site.register(UsedToken)

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
        "send_qr_action",
        "is_superuser"
    ]
    
    list_display_links = ["email"]
    
    # Fields to allow search and filter options
    search_fields = ["email", "first_name", "last_name"]
    list_filter = ('is_staff', 'is_active')
    
    def username_link(self, obj: object) -> str:
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
    
    def send_qr_action(self, obj: object) -> str:
        """
        Generate an HTML link for triggering the "Generate QR Code" action in the admin interface.

        This method creates a link to the 'qrlink' endpoint with the given object's user ID
        and wraps it in HTML to display a styled button.

        Args:
            obj (object): The object instance for which the QR code generation link is created.
                        Typically, this is an instance of a model in the Django admin interface.

        Returns:
            str: A formatted HTML string representing the QR code generation button.
        """
        # Generate the URL for the 'qrlink' view with the user ID as a keyword argument.
        link = reverse('qrlink', kwargs={'user_id': obj.id})
        
        # Return an HTML string for a button linking to the generated URL.
        return format_html(f'<a class="btn btn-primary" style="margin-right: 5px; margin-left: 5px;" href="{link}">Generate QR Code</a>')
 
    send_qr_action.short_description = "Send QR Code"
    send_qr_action.allow_tags = True
    
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
