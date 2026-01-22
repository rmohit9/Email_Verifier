from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path('login/', views.login, name='login'),
    path('signup/', views.signup, name='signup'),
    path('upload/', views.upload, name='upload'),
    path('verification-results/', views.verification_results, name='verification_results'),
    path('verification-progress/', views.verification_progress, name='verification_progress'),
    path('admin/', views.admin_dashboard, name='admin_dashboard'),
    path('user/', views.user_dashboard, name='user_dashboard'),
    path('settings/', views.settings, name='settings'),
    path('logs/', views.logs, name='logs'),
    path('privacy/', views.privacy, name='privacy'),
    path('terms/', views.terms, name='terms'),
    path('cookie/', views.cookie, name='cookie'),
]
