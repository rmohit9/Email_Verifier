from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

# Create DRF Router
router = DefaultRouter()
router.register(r'jobs', views.VerificationJobViewSet, basename='verificationjob')

urlpatterns = [
    # --- HTML Page Routes ---
    path('', views.home, name='home'),
    path('login/', views.login, name='login'),
    path('signup/', views.signup, name='signup'),
    path('logout/', views.logout_view, name='logout'),
    path('upload/', views.upload, name='upload'),
    path('verification-results/', views.verification_results, name='verification_results'),
    path('verification-progress/', views.verification_progress, name='verification_progress'),
    path('admin-dashboard/', views.admin_dashboard, name='admin_dashboard'),
    path('admin-login/', views.admin_login, name='admin_login'),
    path('user/', views.user_dashboard, name='user_dashboard'),
    path('settings/', views.settings_page, name='settings'),
    path('logs/', views.logs, name='logs'),
    path('privacy/', views.privacy, name='privacy'),
    path('terms/', views.terms, name='terms'),
    path('cookie/', views.cookie, name='cookie'),
    
    # --- DRF API Routes ---
    # This includes /api/jobs/, /api/jobs/{id}/results/, /api/jobs/{id}/download/
    path('api/', include(router.urls)),
    
    # Single verify endpoint
    path('api/verify-single/', views.SingleVerifyView.as_view(), name='api_verify_single'),
]