from django.shortcuts import render, redirect, get_object_or_404
from django.conf import settings
from django.http import HttpResponse
from django.contrib.auth import authenticate, login as auth_login, logout as auth_logout
from django.contrib.auth.models import User
from django.contrib import messages

# --- DRF Imports ---
from rest_framework import viewsets, status, views, permissions, parsers
from rest_framework.response import Response
from rest_framework.decorators import action

# --- Local Imports ---
from .models import VerificationJob, EmailResult
from .serializers import (
    VerificationJobSerializer, 
    EmailResultSerializer, 
    SingleVerifySerializer,
    BulkVerifySerializer
)

# --- Third Party Imports ---
from email_validator import validate_email, EmailNotValidError
import dns.resolver
from celery import shared_task
from django.utils import timezone
from datetime import timedelta
import csv
import io

# ============================================================================
# 1. AUTHENTICATION VIEWS
# ============================================================================

def home(request): return render(request, 'home.html')

def login(request):
    """Log in using Email and Password"""
    if request.user.is_authenticated:
        return redirect('upload')

    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        
        # We treat email as username
        user = authenticate(request, username=email, password=password)
        
        if user is not None:
            auth_login(request, user)
            return redirect('upload')
        else:
            messages.error(request, "Invalid email or password.")
    
    return render(request, 'login.html')

def signup(request):
    """Create account using Email as Username"""
    if request.user.is_authenticated:
        return redirect('upload')

    if request.method == 'POST':
        full_name = request.POST.get('full_name')
        email = request.POST.get('email')
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')

        if password != confirm_password:
            messages.error(request, "Passwords do not match.")
            return render(request, 'signup.html')
        
        if User.objects.filter(username=email).exists():
            messages.error(request, "This email is already registered.")
            return render(request, 'signup.html')

        try:
            # Create User (Set username to email so we can login with email)
            user = User.objects.create_user(
                username=email, 
                email=email, 
                password=password,
                first_name=full_name
            )
            user.save()
            
            auth_login(request, user) # Auto-login
            return redirect('upload')
            
        except Exception as e:
            messages.error(request, f"Error creating account: {str(e)}")

    return render(request, 'signup.html')

def logout_view(request):
    auth_logout(request)
    return redirect('home')

# ============================================================================
# 2. VERIFICATION LOGIC (STEPS 1-3)
# ============================================================================

def get_resolver():
    """ Configure reliable DNS resolver using values from settings.py """
    resolver = dns.resolver.Resolver()
    # resolver.nameservers = settings.DNS_NAMESERVERS
    resolver.timeout = settings.DNS_TIMEOUT
    resolver.lifetime = settings.DNS_LIFETIME
    return resolver

def verify_syntax(email):
    try:
        v = validate_email(email, check_deliverability=False)
        return {"valid": True, "reason": "Syntax is valid", "email": v.normalized, "domain": v.domain}
    except EmailNotValidError as e:
        return {"valid": False, "reason": f"Syntax Error: {str(e)}", "email": email, "domain": None}

def verify_domain(domain):
    if not domain: return {"valid": False, "reason": "No domain"}
    try:
        resolver = get_resolver()
        resolver.resolve(domain, 'NS')
        return {"valid": True, "reason": "Domain exists"}
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return {"valid": False, "reason": "Domain does not exist"}
    except dns.resolver.Timeout:
        return {"valid": False, "reason": "DNS Timeout"}
    except Exception as e:
        return {"valid": False, "reason": f"DNS Error: {str(e)}"}

def verify_mx(domain):
    try:
        resolver = get_resolver()
        answers = resolver.resolve(domain, 'MX')
        mx_records = sorted([str(r.exchange).rstrip('.') for r in answers])
        if not mx_records:
            return {"valid": False, "reason": "No MX records", "mx_records": []}
        return {"valid": True, "reason": "MX records found", "mx_records": mx_records}
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return {"valid": False, "reason": "No MX records", "mx_records": []}
    except Exception as e:
        return {"valid": False, "reason": f"MX Error: {str(e)}", "mx_records": []}

def run_verification_pipeline(email):
    """ Orchestrates Steps 1, 2, and 3 for a single email. """
    result = {
        "email": email, "normalized_email": email, "domain": "",
        "syntax_valid": False, "domain_exists": False, "mx_records_found": False,
        "mx_records": [], "status": "invalid", "reason": ""
    }

    s1 = verify_syntax(email)
    result['syntax_valid'] = s1['valid']
    result['reason'] = s1['reason']
    if not s1['valid']: return result
    
    result['normalized_email'] = s1['email']
    result['domain'] = s1['domain']

    s2 = verify_domain(s1['domain'])
    result['domain_exists'] = s2['valid']
    result['reason'] = s2['reason']
    if not s2['valid']: return result

    s3 = verify_mx(s1['domain'])
    result['mx_records_found'] = s3['valid']
    result['reason'] = s3['reason']
    result['mx_records'] = s3['mx_records']
    
    if s3['valid']:
        result['status'] = "valid"
    
    return result

# ============================================================================
# 3. CELERY TASKS (DB SAVING)
# ============================================================================

@shared_task
def process_email_bulk(job_id, emails):
    """ Background task to process emails and SAVE TO DB. """
    try:
        job = VerificationJob.objects.get(job_id=job_id)
        job.status = 'processing'
        job.save()

        results_to_create = []
        valid_count = 0
        invalid_count = 0
        total = len(emails)
        
        # FIX: Update every 1 email if list is small, otherwise every 10
        update_interval = 1 if total < 100 else 10

        for i, email in enumerate(emails):
            data = run_verification_pipeline(email)
            
            if data['status'] == 'valid':
                valid_count += 1
            else:
                invalid_count += 1

            results_to_create.append(EmailResult(
                job=job,
                email=email,
                normalized_email=data.get('normalized_email'),
                domain=data.get('domain'),
                status=data.get('status'),
                syntax_valid=data.get('syntax_valid'),
                domain_exists=data.get('domain_exists'),
                mx_records_found=data.get('mx_records_found'),
                mx_records=data.get('mx_records'),
                reason=data.get('reason')
            ))

            # Update Progress in DB
            job.processed_count = i + 1
            if job.processed_count % update_interval == 0 or job.processed_count == total:
                job.progress_percentage = (job.processed_count / total) * 100
                job.save()

        EmailResult.objects.bulk_create(results_to_create)

        job.valid_count = valid_count
        job.invalid_count = invalid_count
        job.processed_count = total
        job.progress_percentage = 100.0
        job.status = 'completed'
        job.completed_at = timezone.now()
        job.save()

    except Exception as e:
        if 'job' in locals():
            job.status = 'failed'
            job.error_message = str(e)
            job.save()
        print(f"Error in background task: {e}")

@shared_task
def cleanup_old_jobs(days=30):
    cutoff_date = timezone.now() - timedelta(days=days)
    VerificationJob.objects.filter(created_at__lt=cutoff_date).delete()

# ============================================================================
# 4. DRF API VIEWS
# ============================================================================

class SingleVerifyView(views.APIView):
    """ API Endpoint to verify a single email instantly. """
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = SingleVerifySerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            result = run_verification_pipeline(email)
            return Response({'email': email, 'result': result}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class VerificationJobViewSet(viewsets.ModelViewSet):
    """
    API Endpoint for managing Bulk Verification Jobs (Saved to DB).
    """
    queryset = VerificationJob.objects.all().order_by('-created_at')
    serializer_class = VerificationJobSerializer
    parser_classes = (parsers.JSONParser, parsers.MultiPartParser, parsers.FormParser)

    def get_queryset(self):
        # Users see only their jobs; Staff see all
        user = self.request.user
        if user.is_authenticated and not user.is_staff:
            return VerificationJob.objects.filter(user=user).order_by('-created_at')
        return super().get_queryset()

    def create(self, request, *args, **kwargs):
        """ Handles File Upload and saves to DB """
        serializer = BulkVerifySerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        emails = serializer.validated_data.get('emails', [])
        file_obj = serializer.validated_data.get('file')
        filename = "api_upload"

        if file_obj:
            filename = file_obj.name
            try:
                decoded_file = file_obj.read().decode('utf-8')
                if filename.endswith('.csv'):
                    reader = csv.reader(io.StringIO(decoded_file))
                    next(reader, None) # Skip Header
                    emails = [row[0].strip() for row in reader if row]
                elif filename.endswith('.txt'):
                    emails = [line.strip() for line in decoded_file.split('\n') if line.strip()]
                else:
                    return Response({"error": "Only .csv or .txt supported"}, status=400)
            except Exception as e:
                return Response({"error": f"File read error: {str(e)}"}, status=400)

        emails = list(set(emails))
        if not emails:
            return Response({"error": "No valid emails found."}, status=400)

        # CREATE JOB IN DATABASE
        job = VerificationJob.objects.create(
            user=request.user if request.user.is_authenticated else None,
            filename=filename,
            total_count=len(emails),
            status='pending'
        )

        # Trigger Celery (Persistent Mode)
        process_email_bulk.delay(str(job.job_id), emails)

        job_serializer = self.get_serializer(job)
        return Response(job_serializer.data, status=status.HTTP_201_CREATED)

    @action(detail=True, methods=['get'])
    def results(self, request, pk=None):
        """ Get paginated results from DB """
        job = self.get_object()
        results = EmailResult.objects.filter(job=job)
        
        status_filter = request.query_params.get('status')
        if status_filter:
            results = results.filter(status=status_filter)

        page = self.paginate_queryset(results)
        if page is not None:
            serializer = EmailResultSerializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = EmailResultSerializer(results, many=True)
        return Response(serializer.data)

    @action(detail=True, methods=['get'])
    def download(self, request, pk=None):
        """ Download CSV from DB """
        job = self.get_object()
        results = EmailResult.objects.filter(job=job)

        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = f'attachment; filename="results_{job.job_id}.csv"'
        
        writer = csv.writer(response)
        writer.writerow(['Email', 'Status', 'Reason', 'Syntax', 'Domain', 'MX'])
        
        for r in results:
            writer.writerow([r.email, r.status, r.reason, r.syntax_valid, r.domain_exists, r.mx_records_found])
            
        return response

# ============================================================================
# 5. OTHER STANDARD PAGE VIEWS
# ============================================================================

def upload(request): return render(request, 'upload.html')
def verification_results(request): return render(request, 'verification-results.html')
def verification_progress(request): return render(request, 'verification-progress.html')
def user_dashboard(request): return render(request, 'user.html')
def settings_page(request): return render(request, 'settings.html')
def logs(request): return render(request, 'logs.html')
def privacy(request): return render(request, 'privacy.html')
def terms(request): return render(request, 'termandcondition.html')
def cookie(request): return render(request, 'cookie.html')

def admin_dashboard(request):
    recent_jobs = VerificationJob.objects.all().order_by('-created_at')[:10]
    return render(request, 'admin.html', {'recent_jobs': recent_jobs})

def admin_login(request):
    if request.method == "POST":
        return redirect('admin_dashboard')
    return render(request, 'admin_login.html')