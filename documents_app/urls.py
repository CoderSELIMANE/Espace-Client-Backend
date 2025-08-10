from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenRefreshView
from . import views

# Router pour les ViewSets d'administration
admin_router = DefaultRouter()
admin_router.register(r'users', views.AdminUserViewSet, basename='admin-users')

app_name = 'documents_app'

urlpatterns = [
    # Authentification
    path('api/register/', views.register_view, name='register'),
    path('api/login/', views.login_view, name='login'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/profile/', views.user_profile_view, name='user_profile'),
    path('api/stats/', views.user_stats_view, name='user_stats'),

    # Documents
    path('api/documents/', views.DocumentListView.as_view(), name='document_list'),
    path('api/upload/', views.DocumentUploadView.as_view(), name='document_upload'),
    path('api/documents/<int:pk>/', views.DocumentDetailView.as_view(), name='document_detail'),
    path('api/documents/<int:document_id>/download/', views.download_document_view, name='document_download'),
    path('documents/<int:document_id>/preview/', views.preview_document_view, name='preview_document'),
    path('test-auth/', views.test_auth_view, name='test_auth'),
    path('test-download/<int:document_id>/', views.download_document_view, name='test_download'),
    path('test-filename/<int:document_id>/', views.test_filename_view, name='test_filename'),
    path('test-simple/<int:document_id>/', views.test_download_simple, name='test_simple'),

    # Administration moderne avec ViewSets
    path('api/admin/', include(admin_router.urls)),

    # Anciennes vues d'administration (compatibilité)
    path('api/admin/users/', views.admin_list_users, name='admin_list_users'),
    path('api/admin/users/create/', views.admin_create_user, name='admin_create_user'),
    path('api/admin/users/<int:user_id>/delete/', views.admin_delete_user, name='admin_delete_user'),
    path('api/admin/users/<int:user_id>/promote/', views.admin_promote_user, name='admin_promote_user'),
    path('api/admin/stats/', views.admin_stats, name='admin_stats'),
]
