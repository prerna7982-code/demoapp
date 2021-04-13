from django.contrib import admin
from django.utils.translation import ugettext_lazy as _

from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import CustomUser

@admin.register(CustomUser)
class UserAdmin(BaseUserAdmin):
    fieldsets = (
        (None, {'fields': ('username','full_name', 'password','email','photo',)}),
        (_('Personal info'), {'fields': ('first_name', 'last_name')}),
        (_('Permissions'), {'fields': ('is_active', 'is_staff', 'is_superuser',
                                       'groups', 'user_permissions')}),
        (_('Important dates'), {'fields': ('last_login', 'date_joined')}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('username','full_name','email','photo','password1', 'password2'),
        }),
    )
    list_display = ('username', 'full_name','email',)
    search_fields = ('username', 'full_name','email')
    ordering = ('username','email')
    # inlines = (UserProfileInline, )
