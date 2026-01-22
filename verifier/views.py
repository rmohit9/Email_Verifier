from django.shortcuts import render
from django.template.loader import render_to_string
from django.http import HttpResponse

def home(request):
    return render(request, 'home.html')

def login(request):
    return render(request, 'login.html')

def signup(request):
    return render(request, 'signup.html')

def upload(request):
    return render(request, 'upload.html')

def verification_results(request):
    return render(request, 'verification-results.html')

def verification_progress(request):
    return render(request, 'verification-progress.html')

def admin_dashboard(request):
    return render(request, 'admin.html')

def user_dashboard(request):
    return render(request, 'user.html')

def settings(request):
    return render(request, 'settings.html')

def logs(request):
    return render(request, 'logs.html')

def privacy(request):
    return render(request, 'privacy.html')

def terms(request):
    return render(request, 'termandcondition.html')

def cookie(request):
    return render(request, 'cookie.html')
