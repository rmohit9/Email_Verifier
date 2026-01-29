from django.shortcuts import render, redirect, get_object_or_404
from django.conf import settings
from django.http import HttpResponse
from django.contrib.auth import authenticate, login as auth_login, logout as auth_logout
from django.contrib.auth.models import User
from django.contrib import messages
from django.db.models import F

# --- DRF Imports ---
from rest_framework import viewsets, status, views, permissions, parsers
from rest_framework.response import Response
from rest_framework.decorators import action
from rest_framework.throttling import ScopedRateThrottle

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
import smtplib
import socket
import requests


# ============================================================================
# 0. GLOBAL DATA (Disposable Domains)
# ============================================================================

# GitHub Raw URL for the blocklist
DISPOSABLE_LIST_URL = "https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/master/disposable_email_blocklist.conf"
DISPOSABLE_DOMAINS_CACHE = set()

def load_disposable_domains():
    """ Fetches the blocklist from GitHub and MERGES it with our fallback list. """
    global DISPOSABLE_DOMAINS_CACHE
    if DISPOSABLE_DOMAINS_CACHE:
        return DISPOSABLE_DOMAINS_CACHE

    print("DEBUG: Fetching disposable domains from GitHub...")
    
    # 1. Define Fallback List (Always keep these active)
    fallback_domains = {
        'mailinator.com', 'guerrillamail.com', '10minutemail.com', 'yopmail.com',
        'tempmail.com', 'temp-mail.org', 'throwawaymail.com', 'sharklasers.com',
        'getairmail.com', 'mailfa.com', 'mytemp.email'
    }

    try:
        response = requests.get(DISPOSABLE_LIST_URL, timeout=5)
        if response.status_code == 200:
            github_domains = {line.strip().lower() for line in response.text.splitlines() if line.strip()}
            
            # 2. MERGE LISTS (GitHub + Fallback)
            DISPOSABLE_DOMAINS_CACHE = github_domains.union(fallback_domains)
            
            print(f"DEBUG: Successfully loaded {len(DISPOSABLE_DOMAINS_CACHE)} disposable domains (GitHub + Fallback).")
        else:
            print(f"DEBUG ERROR: GitHub returned {response.status_code}. Using fallback.")
            DISPOSABLE_DOMAINS_CACHE = fallback_domains
            
    except Exception as e:
        print(f"DEBUG ERROR [Disposable Fetch]: {str(e)}")
        DISPOSABLE_DOMAINS_CACHE = fallback_domains
    
    return DISPOSABLE_DOMAINS_CACHE

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
            print(f"DEBUG ERROR [Signup]: {str(e)}")
            messages.error(request, f"Error creating account: {str(e)}")

    return render(request, 'signup.html')

def logout_view(request):
    auth_logout(request)
    return redirect('home')

# ============================================================================
# 2. VERIFICATION LOGIC
# ============================================================================

def get_resolver():
    resolver = dns.resolver.Resolver()
    resolver.timeout = settings.DNS_TIMEOUT
    resolver.lifetime = settings.DNS_LIFETIME
    return resolver

def verify_syntax(email):
    try:
        v = validate_email(email, check_deliverability=False)
        return {"valid": True, "reason": "Syntax is valid", "email": v.normalized, "domain": v.domain}
    except EmailNotValidError as e:
        print(f"DEBUG ERROR [Syntax]: {str(e)} for email '{email}'")
        return {"valid": False, "reason": f"Syntax Error: {str(e)}", "email": email, "domain": None}

def verify_disposable(domain):
    """ Step 2: Checks if domain is in the GitHub blocklist. """
    blocked_domains = load_disposable_domains() # Uses cache
    if domain in blocked_domains:
        return {"valid": False, "reason": "Disposable/Temporary Email Detected"}
    return {"valid": True, "reason": "Safe Domain"}

def verify_domain(domain):
    if not domain: return {"valid": False, "reason": "No domain"}
    try:
        get_resolver().resolve(domain, 'NS')
        return {"valid": True, "reason": "Domain exists"}
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        print(f"DEBUG ERROR [Domain DNS]: NXDOMAIN/NoAnswer for '{domain}'")
        return {"valid": False, "reason": "Domain does not exist"}
    except Exception as e:
        print(f"DEBUG ERROR [Domain DNS]: {str(e)} for '{domain}'")
        return {"valid": False, "reason": f"DNS Error: {str(e)}"}

def verify_mx(domain):
    try:
        answers = get_resolver().resolve(domain, 'MX')
        mx_records = sorted([str(r.exchange).rstrip('.') for r in answers])
        if not mx_records: 
            print(f"DEBUG ERROR [MX]: No MX records returned for '{domain}'")
            return {"valid": False, "reason": "No MX records", "mx_records": []}
        return {"valid": True, "reason": "MX records found", "mx_records": mx_records}
    except Exception as e:
        print(f"DEBUG ERROR [MX]: {str(e)} for '{domain}'")
        return {"valid": False, "reason": "No MX records", "mx_records": []}

def smtp_check_advanced(email, sender_email='verify@example.com'):
    """ Debug-enabled SMTP Check """
    try:
        domain = email.split('@')[1]
        mx_records = sorted(dns.resolver.resolve(domain, 'MX'), key=lambda r: r.preference)
        
        for mx in mx_records:
            mx_host = str(mx.exchange).rstrip('.')
            print(f"  -> Connecting to MX: {mx_host}...") 
            try:
                with smtplib.SMTP(mx_host, 25, timeout=3) as server:
                    server.ehlo()
                    server.mail(sender_email) 
                    code, message = server.rcpt(email)
                    if code == 250: return True, "Valid (250 OK)"
                    elif code == 550: return False, "User not found (550)"
                    else: return False, f"Server responded: {code}"
            except Exception as e:
                print(f"  -> DEBUG ERROR [SMTP Connect] on {mx_host}: {e}")
                continue
        return False, "Connection Failed"
    except Exception as e:
        print(f"DEBUG ERROR [SMTP Setup]: {str(e)}")
        return False, f"DNS Error: {str(e)}"

def run_verification_pipeline(email):
    """ 
    PIPELINE ORDER: Syntax -> Disposable -> Domain -> MX -> SMTP 
    """
    result = {
        "email": email, "normalized_email": email, "domain": "",
        "syntax_valid": False, "domain_exists": False, "mx_records_found": False,
        "mx_records": [], "status": "invalid", "reason": "",
        "is_disposable": False
    }

    # 1. Syntax
    s1 = verify_syntax(email)
    result['syntax_valid'] = s1['valid']
    result['reason'] = s1['reason']
    if not s1['valid']: return result
    
    result['normalized_email'] = s1['email']
    result['domain'] = s1['domain']

    # 2. Disposable Check (Fail Fast, but mark as DISPOSABLE)
    s2 = verify_disposable(result['domain'])
    if not s2['valid']:
        result['status'] = "disposable"  # <--- NEW STATUS
        result['reason'] = s2['reason']
        result['is_disposable'] = True
        return result

    # 3. Domain Check
    s3 = verify_domain(result['domain'])
    result['domain_exists'] = s3['valid']
    result['reason'] = s3['reason']
    if not s3['valid']: return result

    # 4. MX Check
    s4 = verify_mx(result['domain'])
    result['mx_records_found'] = s4['valid']
    result['reason'] = s4['reason']
    result['mx_records'] = s4['mx_records']
    if not s4['valid']: return result

    # 5. SMTP Handshake
    if getattr(settings, 'SMTP_CHECK_ENABLED', False):
        is_smtp_valid, smtp_reason = smtp_check_advanced(result['normalized_email'])
        if is_smtp_valid:
            result['status'] = "valid"
            result['reason'] = "Verified via SMTP"
        else:
            result['status'] = "invalid" 
            result['reason'] = f"SMTP Verification Failed: {smtp_reason}"
    else:
        result['status'] = "valid"
        result['reason'] = "Valid (MX Record Found)"
    
    return result

# ============================================================================
# 3. CELERY TASKS (DB SAVING)
# ============================================================================

@shared_task
def process_email_chunk(job_id, emails_chunk):
    """ Process emails and update DB counts correctly """
    try:
        job = VerificationJob.objects.get(job_id=job_id)
        load_disposable_domains()

        for email in emails_chunk:
            print(f"Processing: {email}...") 
            data = run_verification_pipeline(email)
            
            # Update correct counters
            if data['status'] == 'valid': 
                job.valid_count += 1
            elif data['status'] == 'disposable': 
                job.disposable_count += 1    # <--- NEW COUNTER
            else: 
                job.invalid_count += 1
            
            job.processed_count += 1

            EmailResult.objects.create(
                job=job, email=email, normalized_email=data.get('normalized_email'),
                domain=data.get('domain'), 
                status=data.get('status'), # Save 'disposable' status
                syntax_valid=data.get('syntax_valid'), domain_exists=data.get('domain_exists'),
                mx_records_found=data.get('mx_records_found'), mx_records=data.get('mx_records'),
                reason=data.get('reason'), verified_at=timezone.now(),
                is_disposable=data.get('is_disposable', False)
            )

            if job.total_count > 0:
                job.progress_percentage = (job.processed_count / job.total_count) * 100
            
            if job.processed_count >= job.total_count:
                job.status = 'completed'
                job.completed_at = timezone.now()
                job.progress_percentage = 100.0
            
            job.save()
            
    except Exception as e:
        print(f"CRITICAL ERROR in chunk processing: {str(e)}")

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
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = 'verifications'  # 20/minute

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

    def get_throttles(self):
        """
        Dynamically assign throttle scopes based on the action.
        """
        if self.action == 'create':
            self.throttle_scope = 'uploads'  # Strict limit (5/min)
        else:
            self.throttle_scope = 'user'     # Loose limit (120/min) for polling
            
        return super().get_throttles()

    def get_queryset(self):
        # Users see only their jobs; Staff see all
        user = self.request.user
        if user.is_authenticated and not user.is_staff:
            return VerificationJob.objects.filter(user=user).order_by('-created_at')
        return super().get_queryset()

    def create(self, request, *args, **kwargs):
        """ Handles File Upload and dispatches chunks to Celery """
        serializer = BulkVerifySerializer(data=request.data)
        if not serializer.is_valid():
            print(f"DEBUG ERROR [Upload Validation]: {serializer.errors}")
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
                print(f"DEBUG ERROR [File Read]: {str(e)}")
                return Response({"error": f"File read error: {str(e)}"}, status=400)

        emails = list(set(emails))
        total_emails = len(emails)

        if not emails:
            return Response({"error": "No valid emails found."}, status=400)

        # CREATE JOB IN DATABASE (Start at 0 processed)
        job = VerificationJob.objects.create(
            user=request.user if request.user.is_authenticated else None,
            filename=filename,
            total_count=total_emails,
            status='pending',
            processed_count=0 
        )

        # --- CHUNKING LOGIC ---
        BATCH_SIZE = 50 # Safe size for small worker memory
        for i in range(0, total_emails, BATCH_SIZE):
            chunk = emails[i : i + BATCH_SIZE]
            process_email_chunk.delay(str(job.job_id), chunk)
        # ----------------------

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
def logs(request):
    from .models import VerificationJob
    
    # Get filter parameters
    job_id_input = request.GET.get('job_id', '').strip()
    level = request.GET.get('level', '')
    warning_message = None
    
    # Start with all jobs (they are the logs)
    logs_list = VerificationJob.objects.all().order_by('-created_at')
    
    # Filter by job_id if provided
    if job_id_input:
        try:
            import uuid
            # Try direct UUID match first
            uuid.UUID(job_id_input)
            logs_list = logs_list.filter(job_id=job_id_input)
        except (ValueError, TypeError):
            # Try to match by partial UUID (e.g., "JOB-5405" or just "5405")
            clean_input = job_id_input.replace('JOB-', '').replace('job-', '')
            
            try:
                # Try to find a job with UUID containing this string
                logs_list = logs_list.filter(job_id__icontains=clean_input)
                if not logs_list.exists():
                    warning_message = f"No jobs found matching '{job_id_input}'."
            except Exception as e:
                warning_message = f"Invalid Job ID format. Expected format: 'JOB-xxxx' or full UUID."
    
    # Filter by level/status if provided
    if level:
        logs_list = logs_list.filter(status=level)
    
    return render(request, 'logs.html', {
        'logs': logs_list,
        'warning': warning_message,
        'logs_count': logs_list.count(),
        'job_id_input': job_id_input
    })
def privacy(request): return render(request, 'privacy.html')
def terms(request): return render(request, 'termandcondition.html')
def cookie(request): return render(request, 'cookie.html')

def admin_dashboard(request):
    from django.db.models import Sum, Count
    
    # Fetch basic stats
    total_jobs = VerificationJob.objects.count()
    completed_jobs = VerificationJob.objects.filter(status='completed').count()
    pending_jobs = VerificationJob.objects.filter(status='pending').count()
    processing_jobs = VerificationJob.objects.filter(status='processing').count()
    failed_jobs = VerificationJob.objects.filter(status='failed').count()
    
    total_emails = VerificationJob.objects.aggregate(Sum('total_count'))['total_count__sum'] or 0
    valid_emails = VerificationJob.objects.aggregate(Sum('valid_count'))['valid_count__sum'] or 0
    invalid_emails = VerificationJob.objects.aggregate(Sum('invalid_count'))['invalid_count__sum'] or 0
    disposable_emails = VerificationJob.objects.aggregate(Sum('disposable_count'))['disposable_count__sum'] or 0
    
    # Calculate anomalies (invalid + disposable)
    anomalies = invalid_emails + disposable_emails
    
    # Fetch recent jobs
    recent_jobs = VerificationJob.objects.all().order_by('-created_at')[:10]
    
    stats = {
        'total_jobs': total_jobs,
        'completed_jobs': completed_jobs,
        'total_emails': total_emails,
        'anomalies': anomalies,
        'valid_emails': valid_emails,
        'invalid_emails': invalid_emails,
        'disposable_emails': disposable_emails,
    }
    
    # Analytics data for charts
    analytics = {
        'job_status': {
            'completed': completed_jobs,
            'pending': pending_jobs,
            'processing': processing_jobs,
            'failed': failed_jobs,
        },
        'email_verification': {
            'valid': valid_emails,
            'invalid': invalid_emails,
            'disposable': disposable_emails,
        }
    }
    
    return render(request, 'admin.html', {
        'recent_jobs': recent_jobs,
        'stats': stats,
        'analytics': analytics
    })

def admin_login(request):
    if request.method == "POST":
        return redirect('admin_dashboard')
    return render(request, 'admin_login.html')