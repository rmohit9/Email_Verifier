from django.urls import path
from . import views

urlpatterns = [
    # Page routes
    path('', views.home, name='home'),
    path('login/', views.login, name='login'),
    path('signup/', views.signup, name='signup'),
    path('upload/', views.upload, name='upload'),
    path('verification-results/', views.verification_results, name='verification_results'),
    path('verification-progress/', views.verification_progress, name='verification_progress'),
    path('admin/', views.admin_dashboard, name='admin_dashboard'),
    path('admin-login/', views.admin_login, name='admin_login'),
    path('user/', views.user_dashboard, name='user_dashboard'),
    path('settings/', views.settings, name='settings'),
    path('logs/', views.logs, name='logs'),
    path('privacy/', views.privacy, name='privacy'),
    path('terms/', views.terms, name='terms'),
    path('cookie/', views.cookie, name='cookie'),
    
    # API routes for email verification
    path('api/verify/bulk/', views.create_verification_job, name='create_verification_job'),
    path('api/verify/single/', views.verify_single_email_api, name='verify_single_email_api'),
    path('api/jobs/', views.list_jobs, name='list_jobs'),
    path('api/jobs/<uuid:job_id>/status/', views.get_job_status, name='get_job_status'),
    path('api/jobs/<uuid:job_id>/results/', views.get_job_results, name='get_job_results'),
    path('api/jobs/<uuid:job_id>/download/', views.download_job_results, name='download_job_results'),
]

