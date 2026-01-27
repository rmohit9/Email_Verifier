from django.shortcuts import render, redirect, get_object_or_404
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.core.paginator import Paginator
from django.utils import timezone
from datetime import timedelta
from django.conf import settings  # <--- IMPORT SETTINGS

# --- Models ---
from .models import VerificationJob, EmailResult

# --- Third Party Imports ---
from email_validator import validate_email, EmailNotValidError
import dns.resolver
import json
import csv
import io

# --- Celery Imports ---
from celery import shared_task

# ============================================================================
# 1. VERIFICATION LOGIC (STEPS 1-3)
# ============================================================================

def get_resolver():
    """ Configure reliable DNS resolver using values from settings.py """
    resolver = dns.resolver.Resolver()
    
    # Use settings from settings.py
    resolver.nameservers = settings.DNS_NAMESERVERS
    resolver.timeout = settings.DNS_TIMEOUT
    resolver.lifetime = settings.DNS_LIFETIME
    
    return resolver

def verify_syntax(email):
    """ Step 1: Regex/Syntax Check """
    try:
        v = validate_email(email, check_deliverability=False)
        return {
            "valid": True, "reason": "Syntax is valid",
            "email": v.normalized, "domain": v.domain
        }
    except EmailNotValidError as e:
        return {
            "valid": False, "reason": f"Syntax Error: {str(e)}",
            "email": email, "domain": None
        }

def verify_domain(domain):
    """ Step 2: NS Record Check """
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
    """ Step 3: MX Record Check """
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

    # Step 1
    s1 = verify_syntax(email)
    result['syntax_valid'] = s1['valid']
    result['reason'] = s1['reason']
    if not s1['valid']: return result
    
    result['normalized_email'] = s1['email']
    result['domain'] = s1['domain']

    # Step 2
    s2 = verify_domain(s1['domain'])
    result['domain_exists'] = s2['valid']
    result['reason'] = s2['reason']
    if not s2['valid']: return result

    # Step 3
    s3 = verify_mx(s1['domain'])
    result['mx_records_found'] = s3['valid']
    result['reason'] = s3['reason']
    result['mx_records'] = s3['mx_records']
    
    if s3['valid']:
        result['status'] = "valid"
    
    return result

# ============================================================================
# 2. CELERY TASKS (Background Processing)
# ============================================================================

@shared_task
def process_email_bulk(job_id, emails):
    """ 
    Background task to process a list of emails for a specific job.
    """
    try:
        job = VerificationJob.objects.get(job_id=job_id)
        job.status = 'processing'
        job.save()

        results_to_create = []
        valid_count = 0
        invalid_count = 0
        
        # Use batch size from settings if we needed to chunk (loop logic handles this safely)
        # batch_size = settings.VERIFICATION_BATCH_SIZE 
        
        for email in emails:
            # Run the pipeline
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

            # Update job progress periodically
            job.processed_count += 1
            if job.processed_count % 10 == 0:
                job.progress_percentage = (job.processed_count / job.total_count) * 100
                job.save()

        # Bulk create results
        EmailResult.objects.bulk_create(results_to_create)

        # Final Job Update
        job.valid_count = valid_count
        job.invalid_count = invalid_count
        job.processed_count = job.total_count
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
    """ Cleanup old jobs based on settings or default. """
    cutoff_date = timezone.now() - timedelta(days=days)
    deleted_count, _ = VerificationJob.objects.filter(
        created_at__lt=cutoff_date,
        status__in=['completed', 'failed']
    ).delete()
    return {'deleted_jobs': deleted_count}

# ============================================================================
# 3. PAGE VIEWS
# ============================================================================

def home(request): return render(request, 'home.html')
def login(request): return render(request, 'login.html')
def signup(request): return render(request, 'signup.html')
def upload(request): return render(request, 'upload.html')
def verification_results(request): return render(request, 'verification-results.html')
def verification_progress(request): return render(request, 'verification-progress.html')
def user_dashboard(request): return render(request, 'user.html')
def settings_page(request): return render(request, 'settings.html') # Renamed to avoid conflict with 'settings' import
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

# ============================================================================
# 4. API ENDPOINTS
# ============================================================================

@csrf_exempt
@require_http_methods(["POST"])
def create_verification_job(request):
    try:
        emails = []
        filename = "api_upload"
        
        if request.FILES.get('file'):
            uploaded_file = request.FILES['file']
            filename = uploaded_file.name
            
            if filename.endswith('.csv'):
                decoded_file = uploaded_file.read().decode('utf-8')
                csv_reader = csv.reader(io.StringIO(decoded_file))
                next(csv_reader, None) # Skip header
                for row in csv_reader:
                    if row and row[0].strip(): emails.append(row[0].strip())
            
            elif filename.endswith('.txt'):
                decoded_file = uploaded_file.read().decode('utf-8')
                emails = [line.strip() for line in decoded_file.split('\n') if line.strip()]
            else:
                return JsonResponse({'error': 'Only CSV or TXT allowed'}, status=400)
        
        elif request.content_type == 'application/json':
            data = json.loads(request.body)
            emails = data.get('emails', [])
            filename = data.get('filename', 'api_upload.json')
        
        if not emails:
            return JsonResponse({'error': 'No emails provided'}, status=400)

        emails = list(dict.fromkeys(emails))

        job = VerificationJob.objects.create(
            user=request.user if request.user.is_authenticated else None,
            filename=filename,
            total_count=len(emails),
            status='pending'
        )

        process_email_bulk.delay(str(job.job_id), emails)

        return JsonResponse({
            'job_id': str(job.job_id),
            'status': 'pending',
            'total_count': len(emails),
            'message': 'Job started'
        }, status=201)

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

@require_http_methods(["GET"])
def get_job_status(request, job_id):
    try:
        job = get_object_or_404(VerificationJob, job_id=job_id)
        return JsonResponse({
            'job_id': str(job.job_id),
            'status': job.status,
            'total_count': job.total_count,
            'processed_count': job.processed_count,
            'valid_count': job.valid_count,
            'invalid_count': job.invalid_count,
            'progress_percentage': round(job.progress_percentage, 2),
            'created_at': job.created_at.isoformat(),
            'completed_at': job.completed_at.isoformat() if job.completed_at else None
        })
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=404)

@require_http_methods(["GET"])
def get_job_results(request, job_id):
    try:
        job = get_object_or_404(VerificationJob, job_id=job_id)
        page = int(request.GET.get('page', 1))
        page_size = int(request.GET.get('page_size', 50))
        status_filter = request.GET.get('status')

        results = EmailResult.objects.filter(job=job)
        if status_filter:
            results = results.filter(status=status_filter)

        paginator = Paginator(results, page_size)
        page_obj = paginator.get_page(page)

        data = []
        for r in page_obj:
            data.append({
                'email': r.email,
                'status': r.status,
                'reason': r.reason,
                'verification_time_ms': r.verification_time_ms
            })

        return JsonResponse({
            'job_id': str(job.job_id),
            'total_results': paginator.count,
            'page': page,
            'results': data
        })
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

@require_http_methods(["GET"])
def download_job_results(request, job_id):
    try:
        job = get_object_or_404(VerificationJob, job_id=job_id)
        results = EmailResult.objects.filter(job=job)

        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = f'attachment; filename="results_{job_id}.csv"'
        
        writer = csv.writer(response)
        writer.writerow(['Email', 'Status', 'Reason', 'Syntax Valid', 'Domain Exists', 'MX Found'])
        
        for r in results:
            writer.writerow([r.email, r.status, r.reason, r.syntax_valid, r.domain_exists, r.mx_records_found])
            
        return response
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

@csrf_exempt
@require_http_methods(["POST"])
def verify_single_email_api(request):
    try:
        data = json.loads(request.body)
        email = data.get('email')
        if not email: return JsonResponse({'error': 'Email required'}, status=400)
        
        result = run_verification_pipeline(email)
        return JsonResponse({'email': email, 'result': result})
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

@require_http_methods(["GET"])
def list_jobs(request):
    try:
        jobs = VerificationJob.objects.all().order_by('-created_at')
        if request.user.is_authenticated and not request.user.is_staff:
            jobs = jobs.filter(user=request.user)
            
        paginator = Paginator(jobs, 20)
        page = int(request.GET.get('page', 1))
        page_obj = paginator.get_page(page)
        
        data = []
        for j in page_obj:
            data.append({
                'job_id': str(j.job_id),
                'filename': j.filename,
                'status': j.status,
                'progress': j.progress_percentage,
                'created_at': j.created_at.isoformat()
            })
            
        return JsonResponse({'jobs': data, 'total': paginator.count})
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)