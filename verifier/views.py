from django.shortcuts import render, redirect, get_object_or_404
from django.conf import settings
from django.http import HttpResponse
from django.contrib.auth import authenticate, login as auth_login, logout as auth_logout
from django.contrib.auth.models import User
from django.contrib import messages
from django.db.models import F

from rest_framework import viewsets, status, views, permissions, parsers
from rest_framework.response import Response
from rest_framework.decorators import action
from rest_framework.throttling import ScopedRateThrottle

from .models import VerificationJob, EmailResult
from .serializers import (
    VerificationJobSerializer, 
    EmailResultSerializer, 
    SingleVerifySerializer,
    BulkVerifySerializer
)

from email_validator import validate_email, EmailNotValidError
import dns.resolver
from celery import shared_task
from django.utils import timezone
from datetime import timedelta
import csv
import io
import requests
import re

# ============================================================================
# 0. GLOBAL DATA & LISTS
# ============================================================================

DISPOSABLE_LIST_URL = "https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/master/disposable_email_blocklist.conf"
DISPOSABLE_DOMAINS_CACHE = set()

ROLE_ACCOUNTS = {
    'admin', 'support', 'sales', 'info', 'contact', 'marketing', 
    'hr', 'jobs', 'office', 'billing', 'help', 'noreply', 'no-reply',
    'webmaster', 'editor', 'press', 'media', 'hello', 'enquiries'
}

FREE_PROVIDERS = {
    'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com', 
    'icloud.com', 'proton.me', 'protonmail.com', 'zoho.com', 'yandex.com',
    'mail.com', 'gmx.com', 'live.com', 'msn.com'
}

# RFC 2606 Reserved Domains (Should be Invalid)
RESERVED_DOMAINS = {
    'example.com', 'example.org', 'example.net', 
    'example.edu', 'test', 'invalid', 'localhost'
}

def load_disposable_domains():
    """ Fetches blocklist and merges with fallback. """
    global DISPOSABLE_DOMAINS_CACHE
    if DISPOSABLE_DOMAINS_CACHE:
        return DISPOSABLE_DOMAINS_CACHE

    print("DEBUG: Fetching disposable domains...")
    fallback_domains = {
        'mailinator.com', 'guerrillamail.com', '10minutemail.com', 'yopmail.com',
        'tempmail.com', 'temp-mail.org', 'throwawaymail.com', 'sharklasers.com',
        'getairmail.com', 'mailfa.com', 'mytemp.email'
    }

    try:
        response = requests.get(DISPOSABLE_LIST_URL, timeout=5)
        if response.status_code == 200:
            github_domains = {line.strip().lower() for line in response.text.splitlines() if line.strip()}
            DISPOSABLE_DOMAINS_CACHE = github_domains.union(fallback_domains)
            print(f"DEBUG: Loaded {len(DISPOSABLE_DOMAINS_CACHE)} domains.")
        else:
            DISPOSABLE_DOMAINS_CACHE = fallback_domains
    except Exception as e:
        print(f"DEBUG ERROR [Disposable Fetch]: {e}")
        DISPOSABLE_DOMAINS_CACHE = fallback_domains
    
    return DISPOSABLE_DOMAINS_CACHE

# ============================================================================
# 1. AUTHENTICATION & PAGE VIEWS
# ============================================================================

def home(request): return render(request, 'home.html')
def upload(request): return render(request, 'upload.html')
def verification_results(request): return render(request, 'verification-results.html')
def verification_progress(request): return render(request, 'verification-progress.html')
def user_dashboard(request): return render(request, 'user.html')
def settings_page(request): return render(request, 'settings.html')
def logs(request): return render(request, 'logs.html')
def privacy(request): return render(request, 'privacy.html')
def terms(request): return render(request, 'termandcondition.html')
def cookie(request): return render(request, 'cookie.html')

def login(request):
    if request.user.is_authenticated: return redirect('upload')
    if request.method == 'POST':
        user = authenticate(request, username=request.POST.get('email'), password=request.POST.get('password'))
        if user:
            auth_login(request, user)
            return redirect('upload')
        messages.error(request, "Invalid email or password.")
    return render(request, 'login.html')

def signup(request):
    if request.user.is_authenticated: return redirect('upload')
    if request.method == 'POST':
        try:
            user = User.objects.create_user(username=request.POST.get('email'), email=request.POST.get('email'), password=request.POST.get('password'), first_name=request.POST.get('full_name'))
            user.save()
            auth_login(request, user)
            return redirect('upload')
        except Exception as e:
            messages.error(request, f"Error: {e}")
    return render(request, 'signup.html')

def logout_view(request):
    auth_logout(request)
    return redirect('home')

def admin_dashboard(request):
    recent_jobs = VerificationJob.objects.all().order_by('-created_at')[:10]
    return render(request, 'admin.html', {'recent_jobs': recent_jobs})

def admin_login(request):
    if request.method == "POST": return redirect('admin_dashboard')
    return render(request, 'admin_login.html')

# ============================================================================
# 2. VERIFICATION LOGIC (Pure DNS Pipeline)
# ============================================================================

def get_resolver():
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3.0 # Fast timeout
    resolver.lifetime = 3.0
    return resolver

# STEP 1: Syntax
def verify_syntax(email):
    try:
        v = validate_email(email, check_deliverability=False)
        return {"valid": True, "reason": "Syntax is valid", "email": v.normalized, "domain": v.domain}
    except EmailNotValidError as e:
        return {"valid": False, "reason": f"Syntax Error: {str(e)}", "email": email, "domain": None}

# STEP 2: Disposable
def verify_disposable(domain):
    blocked_domains = load_disposable_domains()
    if domain in blocked_domains:
        return {"valid": False, "reason": "Disposable/Temporary Email Detected"}
    return {"valid": True, "reason": "Safe Domain"}

# STEP 3: Gibberish & Typo (Improved)
def verify_typo_and_gibberish(email):
    try:
        domain = email.split('@')[1].lower()
        local_part = email.split('@')[0].lower()
        
        # 1. Typo Check
        TYPO_MAP = {
            'gnail.com': 'gmail.com', 'gmil.com': 'gmail.com', 
            'yaho.com': 'yahoo.com', 'outlok.com': 'outlook.com',
            'hotmil.com': 'hotmail.com'
        }
        if domain in TYPO_MAP:
            return False, f"Possible Typo: Did you mean {TYPO_MAP[domain]}?"

        # 2. Numeric Density Check (Bot detection)
        # Improvement: Allow high numbers on Free Providers (e.g. phone numbers on gmail)
        if domain not in FREE_PROVIDERS and len(local_part) > 8:
            num_count = len(re.findall(r'[0-9]', local_part))
            if (num_count / len(local_part)) > 0.5:
                return False, "High Numeric Density (Likely Bot)"
    except:
        pass
    return True, "OK"

# STEP 4: Domain DNS (Improved)
def verify_domain(domain):
    if not domain: return {"valid": False, "reason": "No domain"}
    
    # Improvement: Catch Reserved Domains explicitly
    if domain in RESERVED_DOMAINS:
        return {"valid": False, "reason": "Reserved Domain (RFC 2606) - Not Deliverable"}

    try:
        get_resolver().resolve(domain, 'NS')
        return {"valid": True, "reason": "Domain exists"}
    except dns.resolver.NoNameservers:
        return {"valid": False, "reason": "Domain has no nameservers"}
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return {"valid": False, "reason": "Domain does not exist"}
    except Exception as e:
        return {"valid": False, "reason": f"DNS Error: {str(e)}"}

# STEP 5: MX Check
def verify_mx(domain):
    try:
        answers = get_resolver().resolve(domain, 'MX')
        mx_records = sorted([str(r.exchange).rstrip('.') for r in answers])
        if not mx_records: return {"valid": False, "reason": "No MX records", "mx_records": []}
        return {"valid": True, "reason": "MX records found", "mx_records": mx_records}
    except Exception:
        return {"valid": False, "reason": "No MX records", "mx_records": []}

# STEP 6: Professional Enrichment (DNS Security)
def check_dns_security(domain):
    has_security = False
    try:
        # Check SPF
        try:
            txt_records = get_resolver().resolve(domain, 'TXT')
            for txt in txt_records:
                if "v=spf1" in str(txt):
                    has_security = True
                    break
        except: pass
        
        # Check DMARC if SPF not found or just as double check
        if not has_security:
            try:
                get_resolver().resolve(f"_dmarc.{domain}", 'TXT')
                has_security = True
            except: pass
    except:
        pass
    return has_security

def run_verification_pipeline(email):
    result = {
        "email": email, "normalized_email": email, "domain": "",
        "syntax_valid": False, "domain_exists": False, "mx_records_found": False,
        "mx_records": [], "status": "invalid", "reason": "",
        "is_disposable": False,
        "is_role_account": False, "is_free_email": False, "has_dns_security": False
    }

    # 1. Syntax (Fail Fast)
    s1 = verify_syntax(email)
    result['syntax_valid'] = s1['valid']
    result['reason'] = s1['reason']
    if not s1['valid']: return result
    
    result['normalized_email'] = s1['email']
    result['domain'] = s1['domain']
    local_part = result['normalized_email'].split('@')[0].lower()

    # 2. Disposable (Fail Fast)
    s2 = verify_disposable(result['domain'])
    if not s2['valid']:
        result['status'] = "disposable"
        result['reason'] = s2['reason']
        result['is_disposable'] = True
        return result

    # 3. Gibberish/Typo (Fail Fast)
    is_natural, typo_reason = verify_typo_and_gibberish(result['normalized_email'])
    if not is_natural:
        result['status'] = "risky"
        result['reason'] = typo_reason
        return result

    # 4. Domain Check
    s3 = verify_domain(result['domain'])
    result['domain_exists'] = s3['valid']
    result['reason'] = s3['reason']
    if not s3['valid']: return result

    # 5. MX Check
    s4 = verify_mx(result['domain'])
    result['mx_records_found'] = s4['valid']
    result['reason'] = s4['reason']
    result['mx_records'] = s4['mx_records']
    if not s4['valid']: return result
    
    # --- IF HERE, EMAIL IS VALID (MX Found) ---
    # 6. Professional Enrichment (Non-Blocking)
    
    # A. Free vs Corporate
    if result['domain'] in FREE_PROVIDERS:
        result['is_free_email'] = True
    
    # B. Role Account
    if local_part in ROLE_ACCOUNTS:
        result['is_role_account'] = True
        # Note: We rely on the final status block to set this to 'risky'
        # result['status'] = "risky" # Handled below now
        result['reason'] = "Role-Based Address (Generic)"
    
    # C. DNS Security (SPF/DMARC)
    if not result['is_free_email']:
        result['has_dns_security'] = check_dns_security(result['domain'])

    # --- FINAL STATUS DECISION ---
    if result['is_disposable']:
        result['status'] = 'disposable'
    elif result['is_role_account']:
        result['status'] = 'risky'
    elif result['syntax_valid'] and result['domain_exists'] and result['mx_records_found']:
        result['status'] = 'valid'
        # Ensure reason is positive if it wasn't set to "Role-Based..." earlier
        if "Role" not in result['reason']:
            result['reason'] = "Valid (MX Record Found)"
    else:
        # Fallback for anything else (Should normally be caught by early returns)
        result['status'] = 'invalid'

    return result

# ============================================================================
# 3. CELERY TASKS
# ============================================================================

@shared_task
def process_email_chunk(job_id, emails_chunk):
    try:
        job = VerificationJob.objects.get(job_id=job_id)
        load_disposable_domains() 

        for email in emails_chunk:
            print(f"Processing: {email}...") 
            data = run_verification_pipeline(email)
            
            # Update counters
            if data['status'] == 'valid': job.valid_count += 1
            elif data['status'] == 'disposable': job.disposable_count += 1
            else: job.invalid_count += 1
            
            job.processed_count += 1

            EmailResult.objects.create(
                job=job, email=email, normalized_email=data.get('normalized_email'),
                domain=data.get('domain'), 
                status=data.get('status'),
                
                # Standard
                syntax_valid=data.get('syntax_valid'), 
                domain_exists=data.get('domain_exists'),
                mx_records_found=data.get('mx_records_found'), 
                mx_records=data.get('mx_records'),
                is_disposable=data.get('is_disposable', False),
                
                # New Professional Fields
                is_role_account=data.get('is_role_account', False),
                is_free_email=data.get('is_free_email', False),
                has_dns_security=data.get('has_dns_security', False),
                
                reason=data.get('reason'), 
                verified_at=timezone.now()
            )

            if job.total_count > 0:
                job.progress_percentage = (job.processed_count / job.total_count) * 100
            
            if job.processed_count >= job.total_count:
                job.status = 'completed'; job.completed_at = timezone.now(); job.progress_percentage = 100.0
            
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
    permission_classes = [permissions.AllowAny]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = 'verifications'

    def post(self, request):
        serializer = SingleVerifySerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            result = run_verification_pipeline(email)
            return Response({'email': email, 'result': result}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class VerificationJobViewSet(viewsets.ModelViewSet):
    queryset = VerificationJob.objects.all().order_by('-created_at')
    serializer_class = VerificationJobSerializer
    parser_classes = (parsers.JSONParser, parsers.MultiPartParser, parsers.FormParser)

    def get_throttles(self):
        if self.action == 'create': self.throttle_scope = 'uploads'
        else: self.throttle_scope = 'user'
        return super().get_throttles()

    def get_queryset(self):
        user = self.request.user
        if user.is_authenticated and not user.is_staff:
            return VerificationJob.objects.filter(user=user).order_by('-created_at')
        return super().get_queryset()

    def create(self, request, *args, **kwargs):
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
                    next(reader, None)
                    emails = [row[0].strip() for row in reader if row]
                elif filename.endswith('.txt'):
                    emails = [line.strip() for line in decoded_file.split('\n') if line.strip()]
                else:
                    return Response({"error": "Only .csv or .txt supported"}, status=400)
            except Exception as e:
                return Response({"error": f"File read error: {str(e)}"}, status=400)

        emails = list(set(emails))
        total_emails = len(emails)

        if not emails: return Response({"error": "No valid emails found."}, status=400)

        job = VerificationJob.objects.create(
            user=request.user if request.user.is_authenticated else None,
            filename=filename, total_count=total_emails, status='pending', processed_count=0 
        )

        BATCH_SIZE = 50
        for i in range(0, total_emails, BATCH_SIZE):
            chunk = emails[i : i + BATCH_SIZE]
            process_email_chunk.delay(str(job.job_id), chunk)

        job_serializer = self.get_serializer(job)
        return Response(job_serializer.data, status=status.HTTP_201_CREATED)

    @action(detail=True, methods=['get'])
    def results(self, request, pk=None):
        job = self.get_object()
        results = EmailResult.objects.filter(job=job)
        if request.query_params.get('status'):
            results = results.filter(status=request.query_params.get('status'))
        page = self.paginate_queryset(results)
        if page is not None:
            serializer = EmailResultSerializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        serializer = EmailResultSerializer(results, many=True)
        return Response(serializer.data)

    @action(detail=True, methods=['get'])
    def download(self, request, pk=None):
        job = self.get_object()
        results = EmailResult.objects.filter(job=job)
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = f'attachment; filename="results_{job.job_id}.csv"'
        writer = csv.writer(response)
        writer.writerow(['Email', 'Status', 'Reason', 'Syntax', 'Disposable', 'Role', 'Free', 'Secure', 'MX'])
        for r in results:
            writer.writerow([
                r.email, r.status, r.reason, 
                r.syntax_valid, r.is_disposable, r.is_role_account, 
                r.is_free_email, r.has_dns_security, r.mx_records_found
            ])
        return response