from django.contrib import admin
from .models import CustomUser, Document


class CustomUserAdmin(admin.ModelAdmin):
    """Administration personnalisée pour les utilisateurs"""

    # Configuration de base
    list_display = ('email', 'first_name', 'last_name', 'is_active', 'is_staff', 'date_joined')
    list_filter = ('is_active', 'is_staff', 'is_superuser', 'date_joined')
    search_fields = ('email', 'first_name', 'last_name')
    ordering = ('-date_joined',)
    readonly_fields = ('date_joined', 'last_login', 'password')

    # Champs pour l'édition
    fields = ('email', 'first_name', 'last_name', 'is_active', 'is_staff', 'is_superuser', 'last_login', 'date_joined')

    # Exclure les champs problématiques
    exclude = ('username', 'groups', 'user_permissions')


# Enregistrer l'admin
admin.site.register(CustomUser, CustomUserAdmin)


@admin.register(Document)
class DocumentAdmin(admin.ModelAdmin):
    """Administration pour les documents"""
    
    list_display = ('title', 'user', 'document_type', 'uploaded_at', 'is_active')
    list_filter = ('document_type', 'uploaded_at', 'is_active')
    search_fields = ('title', 'user__email', 'description')
    ordering = ('-uploaded_at',)
    readonly_fields = ('uploaded_at', 'updated_at', 'file_size', 'file_extension')
    
    fieldsets = (
        ('Informations générales', {
            'fields': ('title', 'description', 'user', 'document_type', 'is_active')
        }),
        ('Fichier', {
            'fields': ('file', 'file_size', 'file_extension')
        }),
        ('Dates', {
            'fields': ('uploaded_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    def get_queryset(self, request):
        qs = super().get_queryset(request)
        if request.user.is_superuser:
            return qs
        return qs.filter(user=request.user)
