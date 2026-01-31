from django.shortcuts import render, redirect, get_object_or_404
from django.conf import settings
from django.http import HttpResponse
from django.contrib.auth import authenticate, login as auth_login, logout as auth_logout
from django.contrib.auth.models import User
from django.contrib import messages
from django.db.models import F
import logging

# --- DRF Imports ---
from rest_framework import viewsets, status, views, permissions, parsers, renderers


class CSVRenderer(renderers.BaseRenderer):
    """Simple CSV renderer for downloads"""
    media_type = 'text/csv'
    format = 'csv'
    charset = 'utf-8'

    def render(self, data, media_type=None, renderer_context=None):
        # If a Django HttpResponse is returned from the view, DRF will bypass renderers.
        # This renderer exists to satisfy content negotiation when Accept: text/csv is used.
        return data
from rest_framework.response import Response
from rest_framework.decorators import action
from rest_framework.throttling import ScopedRateThrottle

# --- Local Imports ---
from .models import VerificationJob, EmailResult, EmailCampaign, CampaignRecipient, CampaignLog
from .serializers import (
    VerificationJobSerializer, 
    EmailResultSerializer, 
    SingleVerifySerializer,
    BulkVerifySerializer,
    EmailCampaignSerializer,
    EmailCampaignCreateSerializer,
    CampaignRecipientSerializer,
    CampaignLogSerializer
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
import logging

logger = logging.getLogger(__name__)


class BrevoAPIClient:
    """
    Lightweight in-file Brevo client (moved from brevo_service.py)
    """
    BASE_URL = "https://api.brevo.com/v3"

    def __init__(self, api_key: str = None):
        import os
        self.api_key = api_key or os.getenv('BREVO_API_KEY')
        if not self.api_key:
            raise ValueError("BREVO_API_KEY environment variable is not set")

        self.headers = {
            "api-key": self.api_key,
            "Content-Type": "application/json"
        }

    def send_email(self, to_email, subject, html_content, sender_name=None, sender_email=None, reply_to=None, tags=None, custom_headers=None):
        from django.conf import settings
        import requests

        sender_name = sender_name or getattr(settings, 'BREVO_SENDER_NAME', 'Email Campaign')
        sender_email = sender_email or getattr(settings, 'BREVO_SENDER_EMAIL')
        if not sender_email:
            raise ValueError("BREVO_SENDER_EMAIL is not configured")

        payload = {
            "sender": {"name": sender_name, "email": sender_email},
            "to": [{"email": to_email}],
            "subject": subject,
            "htmlContent": html_content,
        }

        if reply_to:
            payload["replyTo"] = {"email": reply_to}
        if tags:
            payload["tags"] = tags
        if custom_headers:
            payload["headers"] = custom_headers

        try:
            response = requests.post(f"{self.BASE_URL}/smtp/email", json=payload, headers=self.headers, timeout=10)
            if response.status_code in (200, 201):
                data = response.json()
                return {"success": True, "message_id": data.get('messageId'), "status_code": response.status_code}
            else:
                return {"success": False, "error": response.text, "status_code": response.status_code}
        except requests.exceptions.Timeout:
            return {"success": False, "error": "Request timeout while sending email to Brevo API"}
        except requests.exceptions.RequestException as e:
            return {"success": False, "error": f"Request failed: {str(e)}"}
        except Exception as e:
            return {"success": False, "error": f"Unexpected error: {str(e)}"}


# Celery tasks moved from verifier/tasks.py into this module so we can remove the external file
from celery import shared_task


@shared_task(bind=True, max_retries=3)
def send_campaign_emails(self, campaign_id):
    from django.utils import timezone
    import time
    try:
        campaign = EmailCampaign.objects.get(campaign_id=campaign_id)
        campaign.status = 'sending'
        campaign.save(update_fields=['status', 'updated_at'])

        CampaignLog.objects.create(campaign=campaign, level='info', message=f"Starting to send campaign '{campaign.subject}' to {campaign.total_recipients} recipients")

        pending_recipients = CampaignRecipient.objects.filter(campaign=campaign, status='pending').values_list('email', flat=True)
        if not pending_recipients:
            campaign.status = 'completed'
            campaign.sent_at = timezone.now()
            campaign.save(update_fields=['status', 'sent_at', 'updated_at'])
            CampaignLog.objects.create(campaign=campaign, level='info', message="Campaign completed. No pending recipients.")
            return

        brevo_client = BrevoAPIClient()

        sent_count = 0
        failed_count = 0
        batch_size = getattr(campaign, 'batch_size', 50) or 50
        delay_between_batches = getattr(campaign, 'delay_between_batches', 1.0) or 1.0

        for i, email in enumerate(pending_recipients):
            try:
                result = brevo_client.send_email(to_email=email, subject=campaign.subject, html_content=campaign.message, tags=['campaign', f'campaign-{campaign_id}'])
                recipient = CampaignRecipient.objects.get(campaign=campaign, email=email)

                if result.get('success'):
                    recipient.status = 'sent'
                    recipient.sent_at = timezone.now()
                    recipient.brevo_message_id = result.get('message_id')
                    recipient.save(update_fields=['status', 'sent_at', 'brevo_message_id'])
                    sent_count += 1
                else:
                    recipient.status = 'failed'
                    recipient.error_message = result.get('error', 'Unknown error')
                    recipient.save(update_fields=['status', 'error_message'])
                    failed_count += 1
                    CampaignLog.objects.create(campaign=campaign, level='error', message=f"Failed to send to {email}: {result.get('error')}", recipient=recipient)

                campaign.sent_count = sent_count
                campaign.failed_count = failed_count
                campaign.update_progress()

                if (i + 1) % int(batch_size) == 0:
                    time.sleep(float(delay_between_batches))

            except CampaignRecipient.DoesNotExist:
                failed_count += 1
            except Exception as e:
                failed_count += 1

        campaign.status = 'completed'
        campaign.sent_at = timezone.now()
        campaign.save(update_fields=['status', 'sent_at', 'updated_at'])
        CampaignLog.objects.create(campaign=campaign, level='success', message=f"Campaign completed. Sent: {sent_count}, Failed: {failed_count}")

    except EmailCampaign.DoesNotExist:
        logger.error(f"Campaign {campaign_id} not found")
    except Exception as e:
        logger.error(f"Error in send_campaign_emails task: {str(e)}")
        try:
            campaign = EmailCampaign.objects.get(campaign_id=campaign_id)
            campaign.status = 'failed'
            campaign.error_message = str(e)
            campaign.save(update_fields=['status', 'error_message', 'updated_at'])
            CampaignLog.objects.create(campaign=campaign, level='error', message=f"Campaign failed with error: {str(e)}")
        except EmailCampaign.DoesNotExist:
            pass
        raise self.retry(exc=e, countdown=60 * (2 ** self.request.retries))


@shared_task
def cleanup_old_campaigns(days=30):
    from django.utils import timezone
    from datetime import timedelta
    cutoff_date = timezone.now() - timedelta(days=days)
    deleted_count, _ = EmailCampaign.objects.filter(status='draft', created_at__lt=cutoff_date).delete()
    logger.info(f"Cleaned up {deleted_count} old draft campaigns")
    return deleted_count


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

    # Per-job results snapshot endpoints and per-job CSV export were removed.
    # Use the collection-level export endpoint at /api/jobs/download/ to export visible/filtered jobs.

    @action(detail=False, methods=['get'], url_path='download', renderer_classes=[renderers.JSONRenderer, CSVRenderer])
    def export_jobs(self, request):
        """Export verification jobs (filtered) as CSV"""
        qs = self.get_queryset().order_by('-created_at')

        job_id = request.GET.get('job_id', '').strip()
        level = request.GET.get('level', '').strip()

        if job_id:
            # support partial job id or UUID
            qs = qs.filter(job_id__icontains=job_id)

        if level:
            qs = qs.filter(status=level)

        filename = 'verification_jobs_export.csv'
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = f'attachment; filename="{filename}"'

        writer = csv.writer(response)
        writer.writerow(['No', 'Job ID', 'Filename', 'Status', 'Created At', 'Total', 'Valid', 'Invalid', 'Disposable', 'Progress'])

        for i, job in enumerate(qs, start=1):
            writer.writerow([
                i,
                job.job_id,
                job.filename or '',
                job.status,
                job.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                job.total_count,
                job.valid_count,
                job.invalid_count,
                job.disposable_count,
                f"{job.progress_percentage:.0f}%"
            ])

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
    if not request.user.is_staff:
        return redirect('home')
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


# ============================================================================
# EMAIL CAMPAIGN ENDPOINTS (Admin Only)
# ============================================================================

def email_campaign(request):
    """
    Admin page to create and manage email campaigns
    """
    if not request.user.is_staff:
        return redirect('home')
    
    context = {}
    return render(request, 'email_campaign.html', context)


class EmailCampaignViewSet(viewsets.ModelViewSet):
    """
    API ViewSet for email campaigns
    Supports: list, create, retrieve, update, destroy, send
    All logic implemented directly in views (no Celery dependency)
    """
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = None  # Set dynamically based on action
    
    def get_queryset(self):
        """Only allow users to see their own campaigns"""
        user = self.request.user
        if user.is_staff:
            return EmailCampaign.objects.all()
        return EmailCampaign.objects.filter(user=user)
    
    def get_serializer_class(self):
        """Return appropriate serializer based on action"""
        if self.action == 'create':
            return EmailCampaignCreateSerializer
        return EmailCampaignSerializer
    
    def create(self, request, *args, **kwargs):
        """
        Create campaign from CSV upload with validation
        """
        serializer = EmailCampaignCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        subject = serializer.validated_data.get('subject')
        message = serializer.validated_data.get('message')
        csv_file = serializer.validated_data.get('csv_file')
        
        # Use emails parsed during serializer validation if available
        emails = getattr(serializer, '_emails', None)
        if emails is None:
            # Fallback: parse CSV here (ensure file pointer is at start)
            import csv
            import io
            try:
                csv_file.seek(0)
            except Exception:
                pass

            emails = []
            try:
                csv_content = csv_file.read().decode('utf-8')
                csv_reader = csv.DictReader(io.StringIO(csv_content))
                for row in csv_reader:
                    email = row.get('email', '').strip()
                    if email:
                        emails.append(email)
            except Exception as e:
                logger.error(f"Error parsing CSV: {str(e)}")
                return Response(
                    {'error': f'CSV parsing error: {str(e)}'},
                    status=status.HTTP_400_BAD_REQUEST
                )
        
        # Remove duplicates while preserving order
        seen = set()
        unique_emails = []
        skipped_count = 0
        
        for email in emails:
            email_lower = email.lower()
            if email_lower not in seen:
                unique_emails.append(email)
                seen.add(email_lower)
            else:
                skipped_count += 1
        
        if not unique_emails:
            return Response(
                {'error': 'No valid emails found in CSV'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Create campaign
        campaign = EmailCampaign.objects.create(
            user=request.user,
            subject=subject,
            message=message,
            csv_filename=csv_file.name,
            total_recipients=len(unique_emails),
            skipped_count=skipped_count,
            status='draft'
        )
        
        # Create recipient records in batches
        recipients_to_create = [
            CampaignRecipient(campaign=campaign, email=email)
            for email in unique_emails
        ]
        CampaignRecipient.objects.bulk_create(recipients_to_create, batch_size=1000)
        
        # Log campaign creation
        CampaignLog.objects.create(
            campaign=campaign,
            level='info',
            message=f"Campaign created with {len(unique_emails)} unique recipients (skipped {skipped_count} duplicates)"
        )
        
        logger.info(f"Campaign {campaign.campaign_id} created with {len(unique_emails)} recipients")
        
        return Response(
            EmailCampaignSerializer(campaign).data,
            status=status.HTTP_201_CREATED
        )
    
    @action(detail=True, methods=['post'])
    def send(self, request, pk=None):
        """
        Send campaign emails synchronously with progress tracking
        Implements Brevo API integration, rate limiting, and error handling
        """
        campaign = self.get_object()
        
        # Validate campaign is in draft status
        if campaign.status != 'draft':
            return Response(
                {'error': f'Campaign cannot be sent. Current status: {campaign.status}'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Check that there are recipients
        pending_recipients = list(
            CampaignRecipient.objects.filter(
                campaign=campaign,
                status='pending'
            ).values_list('email', flat=True)
        )
        
        if not pending_recipients:
            return Response(
                {'error': 'No pending recipients to send to'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Update campaign status
        campaign.status = 'sending'
        campaign.save(update_fields=['status', 'updated_at'])
        
        # Log campaign start
        CampaignLog.objects.create(
            campaign=campaign,
            level='info',
            message=f"Starting to send campaign '{campaign.subject}' to {len(pending_recipients)} recipients"
        )
        
        # Initialize Brevo client
        try:
            brevo_client = BrevoAPIClient()
        except ValueError as e:
            campaign.status = 'failed'
            campaign.error_message = str(e)
            campaign.save(update_fields=['status', 'error_message', 'updated_at'])
            CampaignLog.objects.create(
                campaign=campaign,
                level='error',
                message=f"Brevo API configuration error: {str(e)}"
            )
            logger.error(f"Brevo API config error for campaign {campaign.campaign_id}: {str(e)}")
            return Response(
                {'error': f'Brevo API configuration error: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        
        # Send emails in batches with rate limiting
        sent_count = 0
        failed_count = 0
        # Use campaign-specific settings if available, otherwise defaults
        try:
            batch_size = int(getattr(campaign, 'batch_size', 50) or 50)
        except Exception:
            batch_size = 50
        try:
            delay_between_batches = float(getattr(campaign, 'delay_between_batches', 1.0) or 1.0)
        except Exception:
            delay_between_batches = 1.0
        failed_recipients = []
        
        logger.info(f"Starting to send campaign {campaign.campaign_id} to {len(pending_recipients)} recipients")
        
        import time
        
        for i, email in enumerate(pending_recipients):
            try:
                # Send email via Brevo
                result = brevo_client.send_email(
                    to_email=email,
                    subject=campaign.subject,
                    html_content=campaign.message,
                    tags=['campaign', f'campaign-{campaign.campaign_id}']
                )
                
                # Get recipient record
                try:
                    recipient = CampaignRecipient.objects.get(
                        campaign=campaign,
                        email=email
                    )
                    
                    if result.get('success'):
                        recipient.status = 'sent'
                        recipient.sent_at = timezone.now()
                        recipient.brevo_message_id = result.get('message_id')
                        recipient.save(update_fields=['status', 'sent_at', 'brevo_message_id'])
                        
                        sent_count += 1
                        logger.info(f"Email sent to {email} for campaign {campaign.campaign_id}")
                    else:
                            recipient.status = 'failed'
                            error_msg = result.get('error', 'Unknown error')
                            recipient.error_message = error_msg
                            recipient.save(update_fields=['status', 'error_message'])

                            failed_count += 1
                            failed_recipients.append({'email': email, 'error': error_msg})

                            logger.error(f"Failed to send email to {email}: {error_msg}")

                            # Record full API response in campaign logs to aid debugging
                            CampaignLog.objects.create(
                                campaign=campaign,
                                level='error',
                                message=f"Failed to send to {email}: {error_msg}",
                                recipient=recipient
                            )

                            # Abort early on authentication errors (invalid/missing API key)
                            try:
                                lowered = str(error_msg).lower()
                            except Exception:
                                lowered = ''

                            if 'unauthorized' in lowered or 'key not found' in lowered or 'invalid api key' in lowered:
                                campaign.status = 'failed'
                                campaign.error_message = f'Brevo auth error: {error_msg}'
                                campaign.save(update_fields=['status', 'error_message', 'updated_at'])
                                CampaignLog.objects.create(
                                    campaign=campaign,
                                    level='error',
                                    message=f'Aborting campaign due to Brevo auth error: {error_msg}'
                                )
                                logger.error(f"Aborting campaign {campaign.campaign_id} due to Brevo auth error: {error_msg}")
                                # Return response immediately since this is an API action
                                return Response(
                                    {'error': 'Brevo authentication error', 'details': error_msg},
                                    status=status.HTTP_502_BAD_GATEWAY
                                )
                
                except CampaignRecipient.DoesNotExist:
                    logger.error(f"Recipient record not found for {email} in campaign {campaign.campaign_id}")
                    failed_count += 1
                    failed_recipients.append({'email': email, 'error': 'Recipient record not found'})
                
                # Update campaign progress and persist counts
                campaign.sent_count = sent_count
                campaign.failed_count = failed_count
                campaign.update_progress()  # This now saves sent_count, failed_count, and progress_percentage
                
                # Apply rate limiting between batches
                if (i + 1) % batch_size == 0 and (i + 1) < len(pending_recipients):
                    logger.info(f"Batch {(i + 1) // batch_size} complete. Applying rate limit delay...")
                    time.sleep(delay_between_batches)
            
            except Exception as e:
                logger.error(f"Error sending email to {email}: {str(e)}")
                failed_count += 1
                failed_recipients.append({'email': email, 'error': str(e)})
                
                try:
                    recipient = CampaignRecipient.objects.get(
                        campaign=campaign,
                        email=email
                    )
                    recipient.status = 'failed'
                    recipient.error_message = str(e)
                    recipient.save(update_fields=['status', 'error_message'])
                    
                    CampaignLog.objects.create(
                        campaign=campaign,
                        level='error',
                        message=f"Exception sending to {email}: {str(e)}",
                        recipient=recipient
                    )
                except CampaignRecipient.DoesNotExist:
                    pass
        
        # Mark campaign as completed and persist all final counts
        campaign.status = 'completed'
        campaign.sent_at = timezone.now()
        campaign.save(update_fields=['status', 'sent_at', 'sent_count', 'failed_count', 'progress_percentage', 'updated_at'])
        
        success_msg = f"Campaign completed. Sent: {sent_count}, Failed: {failed_count}"
        CampaignLog.objects.create(
            campaign=campaign,
            level='success',
            message=success_msg
        )
        
        logger.info(f"Campaign {campaign.campaign_id} sending complete. {success_msg}")
        
        return Response(
            {
                'status': 'completed',
                'message': success_msg,
                'sent': sent_count,
                'failed': failed_count,
                'failed_recipients': failed_recipients[:10],  # Limit to first 10 for response
                'campaign': EmailCampaignSerializer(campaign).data
            },
            status=status.HTTP_200_OK
        )
    
    @action(detail=True, methods=['get'])
    def recipients(self, request, pk=None):
        """
        Get recipients for a campaign with optional status filter, search, and pagination
        """
        campaign = self.get_object()
        status_filter = request.query_params.get('status')
        search = request.query_params.get('search')
        
        recipients = CampaignRecipient.objects.filter(campaign=campaign).order_by('id')
        if status_filter:
            recipients = recipients.filter(status=status_filter)
        if search:
            recipients = recipients.filter(email__icontains=search)
        
        # Paginate results using DRF pagination if configured
        page = self.paginate_queryset(recipients)
        if page is not None:
            serializer = CampaignRecipientSerializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = CampaignRecipientSerializer(recipients, many=True)
        return Response(serializer.data)
    
    @action(detail=True, methods=['get'])
    def logs(self, request, pk=None):
        """
        Get logs for a campaign
        """
        campaign = self.get_object()
        logs = CampaignLog.objects.filter(campaign=campaign).order_by('-created_at')
        
        # Optional search + status filter
        search = request.query_params.get('search')
        status_filter = request.query_params.get('status')
        if status_filter:
            logs = logs.filter(recipient__status=status_filter)
        if search:
            logs = logs.filter(message__icontains=search) | logs.filter(recipient__email__icontains=search)

        # Paginate if available
        page = self.paginate_queryset(logs)
        if page is not None:
            serializer = CampaignLogSerializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = CampaignLogSerializer(logs, many=True)
        return Response(serializer.data)

    @action(detail=True, methods=['patch'], url_path=r'logs/(?P<log_id>[^/.]+)/edit')
    def edit_log(self, request, pk=None, log_id=None):
        """Edit a specific campaign log (level/message)"""
        campaign = self.get_object()
        if not (request.user.is_staff or campaign.user == request.user):
            return Response({'detail': 'Not permitted'}, status=status.HTTP_403_FORBIDDEN)
        try:
            log = CampaignLog.objects.get(campaign=campaign, id=log_id)
        except CampaignLog.DoesNotExist:
            return Response({'detail': 'Log not found'}, status=status.HTTP_404_NOT_FOUND)

        serializer = CampaignLogSerializer(log, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        # Only allow updating level and message
        allowed = {}
        if 'level' in serializer.validated_data:
            allowed['level'] = serializer.validated_data['level']
        if 'message' in serializer.validated_data:
            allowed['message'] = serializer.validated_data['message']
        for k, v in allowed.items():
            setattr(log, k, v)
        if allowed:
            log.save(update_fields=list(allowed.keys()))
        return Response(CampaignLogSerializer(log).data)

    @action(detail=True, methods=['delete'], url_path=r'logs/(?P<log_id>[^/.]+)/delete')
    def delete_log(self, request, pk=None, log_id=None):
        """Delete a specific campaign log"""
        campaign = self.get_object()
        if not (request.user.is_staff or campaign.user == request.user):
            return Response({'detail': 'Not permitted'}, status=status.HTTP_403_FORBIDDEN)
        deleted, _ = CampaignLog.objects.filter(campaign=campaign, id=log_id).delete()
        if deleted:
            return Response({'deleted': deleted})
        return Response({'detail': 'Log not found'}, status=status.HTTP_404_NOT_FOUND)

    @action(detail=True, methods=['post'], url_path='logs/bulk_delete')
    def logs_bulk_delete(self, request, pk=None):
        """Bulk delete logs for this campaign"""
        campaign = self.get_object()
        if not (request.user.is_staff or campaign.user == request.user):
            return Response({'detail': 'Not permitted'}, status=status.HTTP_403_FORBIDDEN)
        ids = request.data.get('ids', [])
        if not isinstance(ids, list):
            return Response({'error': 'ids must be a list of integers'}, status=status.HTTP_400_BAD_REQUEST)
        deleted, _ = CampaignLog.objects.filter(campaign=campaign, id__in=ids).delete()
        return Response({'deleted': deleted})

    @action(detail=True, methods=['get'], url_path='recipients/export')
    def export_recipients(self, request, pk=None):
        """Export campaign recipients as CSV"""
        campaign = self.get_object()
        if not (request.user.is_staff or campaign.user == request.user):
            return Response({'detail': 'Not permitted'}, status=status.HTTP_403_FORBIDDEN)

        recipients = CampaignRecipient.objects.filter(campaign=campaign).order_by('id')
        response = HttpResponse(content_type='text/csv')
        filename = f'recipients_campaign_{campaign.campaign_id}.csv'
        response['Content-Disposition'] = f'attachment; filename="{filename}"'

        writer = csv.writer(response)
        writer.writerow(['No', 'Email', 'Status', 'Error Message', 'Sent At', 'Brevo Message ID'])
        for i, r in enumerate(recipients, start=1):
            writer.writerow([i, r.email, r.status, r.error_message or '', r.sent_at.isoformat() if r.sent_at else '', r.brevo_message_id or ''])
        return response

    @action(detail=True, methods=['get'], url_path='logs/download', renderer_classes=[CSVRenderer])
    def export_logs(self, request, pk=None):
        """Export campaign logs as CSV"""
        campaign = self.get_object()
        if not (request.user.is_staff or campaign.user == request.user):
            return Response({'detail': 'Not permitted'}, status=status.HTTP_403_FORBIDDEN)

        logs = CampaignLog.objects.filter(campaign=campaign).order_by('-created_at')
        response = HttpResponse(content_type='text/csv')
        filename = f'logs_campaign_{campaign.campaign_id}.csv'
        response['Content-Disposition'] = f'attachment; filename="{filename}"'

        writer = csv.writer(response)
        writer.writerow(['No', 'Log ID', 'Level', 'Message', 'Recipient Email', 'Recipient Status', 'Recipient Error', 'Created At'])
        for i, l in enumerate(logs, start=1):
            rec = l.recipient
            writer.writerow([i, l.id, l.level, l.message, rec.email if rec else '', rec.status if rec else '', rec.error_message if rec else '', l.created_at.isoformat() if l.created_at else ''])
        return response

    @action(detail=True, methods=['post'])
    def cancel(self, request, pk=None):
        """
        Cancel a campaign (only if not sent/failed)
        """
        campaign = self.get_object()
        
        if campaign.status in ['completed', 'failed']:
            return Response(
                {'error': f'Cannot cancel campaign in {campaign.status} status'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Delete all pending recipients
        deleted_count, _ = CampaignRecipient.objects.filter(
            campaign=campaign,
            status='pending'
        ).delete()
        
        campaign.status = 'failed'
        campaign.error_message = 'Campaign cancelled by user'
        campaign.save(update_fields=['status', 'error_message', 'updated_at'])
        
        CampaignLog.objects.create(
            campaign=campaign,
            level='info',
            message=f'Campaign cancelled by user. Deleted {deleted_count} pending recipients.'
        )
        
        logger.info(f"Campaign {campaign.campaign_id} cancelled. Deleted {deleted_count} pending recipients.")
        
        return Response(
            EmailCampaignSerializer(campaign).data,
            status=status.HTTP_200_OK
        )


class CampaignLogAdminViewSet(viewsets.ModelViewSet):
    """Admin API for viewing and managing all campaign logs (staff only)"""
    permission_classes = [permissions.IsAdminUser]
    serializer_class = CampaignLogSerializer
    queryset = CampaignLog.objects.all().order_by('-created_at')

    def get_queryset(self):
        qs = CampaignLog.objects.all().order_by('-created_at')
        search = self.request.query_params.get('search')
        status_filter = self.request.query_params.get('status')
        campaign_id = self.request.query_params.get('campaign')
        if campaign_id:
            qs = qs.filter(campaign__campaign_id=campaign_id)
        if status_filter:
            qs = qs.filter(recipient__status=status_filter)
        if search:
            from django.db.models import Q
            qs = qs.filter(
                Q(message__icontains=search) |
                Q(campaign__subject__icontains=search) |
                Q(recipient__email__icontains=search)
            )
        return qs

    @action(detail=False, methods=['post'], url_path='bulk_delete')
    def bulk_delete(self, request):
        if not request.user.is_staff:
            return Response({'detail': 'Not permitted'}, status=status.HTTP_403_FORBIDDEN)
        ids = request.data.get('ids', [])
        if not isinstance(ids, list):
            return Response({'error': 'ids must be a list'}, status=status.HTTP_400_BAD_REQUEST)
        deleted, _ = CampaignLog.objects.filter(id__in=ids).delete()
        return Response({'deleted': deleted})

    @action(detail=False, methods=['get'], url_path='export')
    def export(self, request):
        if not request.user.is_staff:
            return Response({'detail': 'Not permitted'}, status=status.HTTP_403_FORBIDDEN)

        logs = self.get_queryset()
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="campaign_logs_export.csv"'

        writer = csv.writer(response)
        writer.writerow(['Log ID', 'Campaign Subject', 'Level', 'Message', 'Recipient Email', 'Recipient Status', 'Recipient Error', 'Created At'])
        for l in logs:
            rec = l.recipient
            writer.writerow([
                l.id,
                l.campaign.subject if l.campaign else '',
                l.level,
                l.message,
                rec.email if rec else '',
                rec.status if rec else '',
                rec.error_message if rec else '',
                l.created_at.isoformat() if l.created_at else ''
            ])
        return response

