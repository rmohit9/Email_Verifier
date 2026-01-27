from django.shortcuts import render, redirect, get_object_or_404
from django.template.loader import render_to_string
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.core.paginator import Paginator
from django.db.models import Q
import json
import csv
import io

from .models import VerificationJob, EmailResult
from .tasks import process_email_bulk, verify_single_email


# ============================================================================
# PAGE VIEWS
# ============================================================================

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
    # Get recent jobs for dashboard
    recent_jobs = VerificationJob.objects.all()[:10]
    context = {
        'recent_jobs': recent_jobs
    }
    return render(request, 'admin.html', context)

def admin_login(request):
    if request.method == "POST":
        return redirect('admin_dashboard')
    return render(request, 'admin_login.html')

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


# ============================================================================
# API ENDPOINTS FOR EMAIL VERIFICATION
# ============================================================================

@csrf_exempt
@require_http_methods(["POST"])
def create_verification_job(request):
    """
    Create a new bulk email verification job.
    
    Accepts:
        - JSON: {"emails": ["email1@example.com", "email2@example.com"]}
        - CSV file upload
    
    Returns:
        JSON with job_id and status
    """
    try:
        emails = []
        filename = None
        
        # Check if it's a file upload
        if request.FILES.get('file'):
            uploaded_file = request.FILES['file']
            filename = uploaded_file.name
            
            # Read CSV file
            if filename.endswith('.csv'):
                decoded_file = uploaded_file.read().decode('utf-8')
                csv_reader = csv.reader(io.StringIO(decoded_file))
                
                # Skip header if present
                headers = next(csv_reader, None)
                
                for row in csv_reader:
                    if row and row[0].strip():
                        emails.append(row[0].strip())
            
            # Read TXT file (one email per line)
            elif filename.endswith('.txt'):
                decoded_file = uploaded_file.read().decode('utf-8')
                emails = [line.strip() for line in decoded_file.split('\n') if line.strip()]
            
            else:
                return JsonResponse({
                    'error': 'Unsupported file format. Please upload CSV or TXT file.'
                }, status=400)
        
        # Check if it's JSON data
        elif request.content_type == 'application/json':
            data = json.loads(request.body)
            emails = data.get('emails', [])
            filename = data.get('filename', 'api_upload.json')
        
        else:
            return JsonResponse({
                'error': 'Invalid request. Please provide emails via JSON or file upload.'
            }, status=400)
        
        # Validate that we have emails
        if not emails:
            return JsonResponse({
                'error': 'No emails provided'
            }, status=400)
        
        # Remove duplicates while preserving order
        emails = list(dict.fromkeys(emails))
        
        # Create verification job
        job = VerificationJob.objects.create(
            user=request.user if request.user.is_authenticated else None,
            filename=filename,
            total_count=len(emails),
            status='pending'
        )
        
        # Start Celery task
        process_email_bulk.delay(str(job.job_id), emails)
        
        return JsonResponse({
            'job_id': str(job.job_id),
            'status': 'pending',
            'total_count': len(emails),
            'message': 'Verification job created successfully'
        }, status=201)
        
    except Exception as e:
        return JsonResponse({
            'error': str(e)
        }, status=500)


@require_http_methods(["GET"])
def get_job_status(request, job_id):
    """
    Get the status and progress of a verification job.
    
    Returns:
        JSON with job details and progress
    """
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
            'updated_at': job.updated_at.isoformat(),
            'completed_at': job.completed_at.isoformat() if job.completed_at else None,
            'error_message': job.error_message
        })
        
    except Exception as e:
        return JsonResponse({
            'error': str(e)
        }, status=404)


@require_http_methods(["GET"])
def get_job_results(request, job_id):
    """
    Get the verification results for a job.
    
    Query params:
        - page: Page number (default: 1)
        - page_size: Results per page (default: 50)
        - status: Filter by status (valid, invalid, risky, unknown)
    
    Returns:
        JSON with paginated results
    """
    try:
        job = get_object_or_404(VerificationJob, job_id=job_id)
        
        # Get query parameters
        page = int(request.GET.get('page', 1))
        page_size = int(request.GET.get('page_size', 50))
        status_filter = request.GET.get('status', None)
        
        # Query results
        results = EmailResult.objects.filter(job=job)
        
        if status_filter:
            results = results.filter(status=status_filter)
        
        # Paginate
        paginator = Paginator(results, page_size)
        page_obj = paginator.get_page(page)
        
        # Serialize results
        results_data = []
        for result in page_obj:
            results_data.append({
                'id': result.id,
                'email': result.email,
                'status': result.status,
                'syntax_valid': result.syntax_valid,
                'domain_exists': result.domain_exists,
                'mx_records_found': result.mx_records_found,
                'smtp_valid': result.smtp_valid,
                'is_disposable': result.is_disposable,
                'is_catch_all': result.is_catch_all,
                'reason': result.reason,
                'mx_records': result.mx_records,
                'domain': result.domain,
                'normalized_email': result.normalized_email,
                'verified_at': result.verified_at.isoformat(),
                'verification_time_ms': result.verification_time_ms
            })
        
        return JsonResponse({
            'job_id': str(job.job_id),
            'total_results': paginator.count,
            'page': page,
            'page_size': page_size,
            'total_pages': paginator.num_pages,
            'results': results_data
        })
        
    except Exception as e:
        return JsonResponse({
            'error': str(e)
        }, status=500)


@require_http_methods(["GET"])
def download_job_results(request, job_id):
    """
    Download verification results as CSV.
    
    Returns:
        CSV file download
    """
    try:
        job = get_object_or_404(VerificationJob, job_id=job_id)
        results = EmailResult.objects.filter(job=job)
        
        # Create CSV response
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = f'attachment; filename="verification_results_{job_id}.csv"'
        
        writer = csv.writer(response)
        
        # Write header
        writer.writerow([
            'Email',
            'Status',
            'Normalized Email',
            'Domain',
            'Syntax Valid',
            'Domain Exists',
            'MX Records Found',
            'SMTP Valid',
            'Is Disposable',
            'Is Catch-All',
            'Reason',
            'MX Records',
            'Verification Time (ms)',
            'Verified At'
        ])
        
        # Write data
        for result in results:
            writer.writerow([
                result.email,
                result.status,
                result.normalized_email or '',
                result.domain or '',
                result.syntax_valid,
                result.domain_exists,
                result.mx_records_found,
                result.smtp_valid,
                result.is_disposable,
                result.is_catch_all,
                result.reason or '',
                ', '.join(result.mx_records) if result.mx_records else '',
                result.verification_time_ms,
                result.verified_at.isoformat()
            ])
        
        return response
        
    except Exception as e:
        return JsonResponse({
            'error': str(e)
        }, status=500)


@require_http_methods(["GET"])
def list_jobs(request):
    """
    List all verification jobs for the current user.
    
    Query params:
        - page: Page number (default: 1)
        - status: Filter by status
    
    Returns:
        JSON with paginated job list
    """
    try:
        # Get query parameters
        page = int(request.GET.get('page', 1))
        page_size = int(request.GET.get('page_size', 20))
        status_filter = request.GET.get('status', None)
        
        # Query jobs
        jobs = VerificationJob.objects.all()
        
        if request.user.is_authenticated and not request.user.is_staff:
            jobs = jobs.filter(user=request.user)
        
        if status_filter:
            jobs = jobs.filter(status=status_filter)
        
        # Paginate
        paginator = Paginator(jobs, page_size)
        page_obj = paginator.get_page(page)
        
        # Serialize jobs
        jobs_data = []
        for job in page_obj:
            jobs_data.append({
                'job_id': str(job.job_id),
                'filename': job.filename,
                'status': job.status,
                'total_count': job.total_count,
                'processed_count': job.processed_count,
                'valid_count': job.valid_count,
                'invalid_count': job.invalid_count,
                'progress_percentage': round(job.progress_percentage, 2),
                'created_at': job.created_at.isoformat(),
                'completed_at': job.completed_at.isoformat() if job.completed_at else None
            })
        
        return JsonResponse({
            'total_jobs': paginator.count,
            'page': page,
            'page_size': page_size,
            'total_pages': paginator.num_pages,
            'jobs': jobs_data
        })
        
    except Exception as e:
        return JsonResponse({
            'error': str(e)
        }, status=500)


@csrf_exempt
@require_http_methods(["POST"])
def verify_single_email_api(request):
    """
    Verify a single email address immediately (synchronous).
    
    Accepts:
        JSON: {"email": "test@example.com"}
    
    Returns:
        JSON with verification result
    """
    try:
        data = json.loads(request.body)
        email = data.get('email')
        
        if not email:
            return JsonResponse({
                'error': 'Email address is required'
            }, status=400)
        
        # Create a temporary job for single email
        job = VerificationJob.objects.create(
            user=request.user if request.user.is_authenticated else None,
            total_count=1,
            status='processing'
        )
        
        # Execute verification synchronously
        result = verify_single_email(email, str(job.job_id))
        
        return JsonResponse({
            'email': email,
            'result': result
        })
        
    except Exception as e:
        return JsonResponse({
            'error': str(e)
        }, status=500)

