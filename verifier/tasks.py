"""
Celery tasks for email verification
"""
from celery import shared_task, group, chord
from django.conf import settings
from django.utils import timezone
from django.db import transaction
import time
import smtplib
import socket
import dns.resolver
from email_validator import validate_email, EmailNotValidError

from .models import VerificationJob, EmailResult, DisposableEmailDomain


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def get_resolver():
    """
    Creates a DNS resolver with strict timeouts and reliable nameservers.
    """
    resolver = dns.resolver.Resolver()
    resolver.nameservers = settings.DNS_NAMESERVERS
    resolver.timeout = settings.DNS_TIMEOUT
    resolver.lifetime = settings.DNS_LIFETIME
    return resolver


def verify_syntax(email):
    """
    Checks if the email follows valid formatting rules (Regex).
    Does NOT connect to the internet.
    """
    try:
        v = validate_email(email, check_deliverability=False)
        return {
            "valid": True,
            "reason": "Syntax is valid",
            "email": v.normalized,
            "domain": v.domain
        }
    except EmailNotValidError as e:
        return {
            "valid": False,
            "reason": f"Syntax Error: {str(e)}",
            "email": email,
            "domain": None
        }


def verify_domain(domain):
    """
    Checks if the domain is registered and active using NS records.
    """
    if not domain:
        return {"valid": False, "reason": "No domain provided"}

    try:
        resolver = get_resolver()
        resolver.resolve(domain, 'NS')
        return {
            "valid": True,
            "reason": "Domain exists (NS records found)"
        }
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return {
            "valid": False,
            "reason": "Domain does not exist"
        }
    except dns.resolver.Timeout:
        return {
            "valid": False,
            "reason": "DNS Timeout: Domain is unresponsive"
        }
    except Exception as e:
        return {
            "valid": False,
            "reason": f"DNS Error: {str(e)}"
        }


def verify_mx(domain):
    """
    Checks if the domain has Mail Exchange (MX) records.
    """
    try:
        resolver = get_resolver()
        answers = resolver.resolve(domain, 'MX')
        
        mx_records = sorted([str(r.exchange).rstrip('.') for r in answers])
        
        if not mx_records:
            return {
                "valid": False,
                "reason": "No MX records found",
                "mx_records": []
            }

        return {
            "valid": True,
            "reason": "Valid MX records found",
            "mx_records": mx_records
        }

    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return {
            "valid": False,
            "reason": "No MX records found (Domain cannot receive email)",
            "mx_records": []
        }
    except dns.resolver.Timeout:
        return {
            "valid": False,
            "reason": "DNS Timeout: Could not verify MX records",
            "mx_records": []
        }
    except Exception as e:
        return {
            "valid": False,
            "reason": f"MX Error: {str(e)}",
            "mx_records": []
        }


def verify_smtp(email, mx_records):
    """
    Performs SMTP handshake to verify if the email address exists.
    This is the most accurate but also the slowest check.
    """
    if not settings.SMTP_CHECK_ENABLED or not mx_records:
        return {
            "valid": False,
            "reason": "SMTP check disabled or no MX records",
            "smtp_response": None
        }
    
    # Try the first MX record
    mx_host = mx_records[0]
    
    try:
        # Connect to SMTP server
        with smtplib.SMTP(timeout=settings.SMTP_TIMEOUT) as smtp:
            smtp.connect(mx_host)
            smtp.helo('verifier.com')
            smtp.mail('verify@verifier.com')
            code, message = smtp.rcpt(email)
            
            # 250 means the email exists
            # 550 means it doesn't exist
            # Other codes are ambiguous
            if code == 250:
                return {
                    "valid": True,
                    "reason": "SMTP verification successful",
                    "smtp_response": message.decode() if isinstance(message, bytes) else str(message)
                }
            elif code == 550:
                return {
                    "valid": False,
                    "reason": "Email address does not exist (SMTP 550)",
                    "smtp_response": message.decode() if isinstance(message, bytes) else str(message)
                }
            else:
                return {
                    "valid": False,
                    "reason": f"SMTP returned code {code}",
                    "smtp_response": message.decode() if isinstance(message, bytes) else str(message)
                }
                
    except (smtplib.SMTPServerDisconnected, smtplib.SMTPConnectError, socket.timeout, socket.error) as e:
        return {
            "valid": False,
            "reason": f"SMTP connection failed: {str(e)}",
            "smtp_response": None
        }
    except Exception as e:
        return {
            "valid": False,
            "reason": f"SMTP error: {str(e)}",
            "smtp_response": None
        }


def check_disposable(domain):
    """
    Checks if the domain is a known disposable/temporary email provider.
    """
    if not settings.DISPOSABLE_EMAIL_CHECK_ENABLED:
        return {"is_disposable": False, "reason": "Check disabled"}
    
    try:
        exists = DisposableEmailDomain.objects.filter(
            domain__iexact=domain,
            is_active=True
        ).exists()
        
        if exists:
            return {
                "is_disposable": True,
                "reason": "Domain is a known disposable email provider"
            }
        else:
            return {
                "is_disposable": False,
                "reason": "Domain is not in disposable list"
            }
    except Exception as e:
        return {
            "is_disposable": False,
            "reason": f"Error checking disposable: {str(e)}"
        }


def check_catch_all(domain, mx_records):
    """
    Checks if the domain accepts all emails (catch-all).
    Tests with a random email address.
    """
    if not settings.SMTP_CHECK_ENABLED or not mx_records:
        return {"is_catch_all": False, "reason": "SMTP check disabled"}
    
    # Generate a random email that likely doesn't exist
    import random
    import string
    random_string = ''.join(random.choices(string.ascii_lowercase + string.digits, k=20))
    test_email = f"{random_string}@{domain}"
    
    try:
        mx_host = mx_records[0]
        with smtplib.SMTP(timeout=settings.SMTP_TIMEOUT) as smtp:
            smtp.connect(mx_host)
            smtp.helo('verifier.com')
            smtp.mail('verify@verifier.com')
            code, _ = smtp.rcpt(test_email)
            
            # If random email is accepted, it's likely a catch-all
            if code == 250:
                return {
                    "is_catch_all": True,
                    "reason": "Domain accepts all emails (catch-all detected)"
                }
            else:
                return {
                    "is_catch_all": False,
                    "reason": "Domain does not appear to be catch-all"
                }
    except Exception:
        # If we can't determine, assume it's not catch-all
        return {
            "is_catch_all": False,
            "reason": "Could not determine catch-all status"
        }


# ============================================================================
# CELERY TASKS
# ============================================================================

@shared_task(bind=True, max_retries=3)
def verify_single_email(self, email, job_id):
    """
    Verify a single email address through all verification layers.
    
    Args:
        email: Email address to verify
        job_id: UUID of the verification job
    
    Returns:
        dict: Verification results
    """
    start_time = time.time()
    
    try:
        # Get the job
        job = VerificationJob.objects.get(job_id=job_id)
        
        # Initialize result
        result_data = {
            'email': email,
            'status': 'unknown',
            'syntax_valid': False,
            'domain_exists': False,
            'mx_records_found': False,
            'smtp_valid': False,
            'is_disposable': False,
            'is_catch_all': False,
            'reason': '',
            'mx_records': [],
            'domain': None,
            'normalized_email': None,
        }
        
        # Layer 1: Syntax Validation
        syntax_result = verify_syntax(email)
        result_data['syntax_valid'] = syntax_result['valid']
        result_data['normalized_email'] = syntax_result['email']
        result_data['domain'] = syntax_result['domain']
        
        if not syntax_result['valid']:
            result_data['status'] = 'invalid'
            result_data['reason'] = syntax_result['reason']
        else:
            domain = syntax_result['domain']
            
            # Layer 2: Domain Verification
            domain_result = verify_domain(domain)
            result_data['domain_exists'] = domain_result['valid']
            
            if not domain_result['valid']:
                result_data['status'] = 'invalid'
                result_data['reason'] = domain_result['reason']
            else:
                # Layer 3: MX Records Check
                mx_result = verify_mx(domain)
                result_data['mx_records_found'] = mx_result['valid']
                result_data['mx_records'] = mx_result.get('mx_records', [])
                
                if not mx_result['valid']:
                    result_data['status'] = 'invalid'
                    result_data['reason'] = mx_result['reason']
                else:
                    # Layer 4: Disposable Email Check
                    disposable_result = check_disposable(domain)
                    result_data['is_disposable'] = disposable_result['is_disposable']
                    
                    if disposable_result['is_disposable']:
                        result_data['status'] = 'risky'
                        result_data['reason'] = disposable_result['reason']
                    else:
                        # Layer 5: SMTP Verification (optional, can be slow)
                        smtp_result = verify_smtp(email, result_data['mx_records'])
                        result_data['smtp_valid'] = smtp_result.get('valid', False)
                        
                        # Layer 6: Catch-all Detection
                        catch_all_result = check_catch_all(domain, result_data['mx_records'])
                        result_data['is_catch_all'] = catch_all_result['is_catch_all']
                        
                        # Final status determination
                        if result_data['smtp_valid']:
                            if result_data['is_catch_all']:
                                result_data['status'] = 'risky'
                                result_data['reason'] = 'Valid but domain is catch-all'
                            else:
                                result_data['status'] = 'valid'
                                result_data['reason'] = 'Email verified successfully'
                        else:
                            # MX exists but SMTP failed - mark as risky
                            result_data['status'] = 'risky'
                            result_data['reason'] = smtp_result.get('reason', 'SMTP verification inconclusive')
        
        # Calculate verification time
        verification_time_ms = int((time.time() - start_time) * 1000)
        result_data['verification_time_ms'] = verification_time_ms
        
        # Save result to database
        with transaction.atomic():
            EmailResult.objects.create(
                job=job,
                **result_data
            )
            
            # Update job progress
            job.processed_count += 1
            if result_data['status'] == 'valid':
                job.valid_count += 1
            else:
                job.invalid_count += 1
            
            job.update_progress()
            
            # Check if job is complete
            if job.processed_count >= job.total_count:
                job.status = 'completed'
                job.completed_at = timezone.now()
                job.save()
        
        return result_data
        
    except VerificationJob.DoesNotExist:
        raise Exception(f"Job {job_id} not found")
    except Exception as e:
        # Retry on failure
        raise self.retry(exc=e, countdown=5)


@shared_task(bind=True)
def process_email_bulk(self, job_id, emails):
    """
    Process a bulk list of emails asynchronously.
    
    Args:
        job_id: UUID of the verification job
        emails: List of email addresses to verify
    
    Returns:
        dict: Job completion status
    """
    try:
        # Get the job
        job = VerificationJob.objects.get(job_id=job_id)
        job.status = 'processing'
        job.save()
        
        # Create a group of tasks for parallel processing
        # Process in batches to avoid overwhelming the system
        batch_size = settings.VERIFICATION_BATCH_SIZE
        
        tasks = []
        for i in range(0, len(emails), batch_size):
            batch = emails[i:i + batch_size]
            batch_tasks = [verify_single_email.s(email, str(job_id)) for email in batch]
            tasks.extend(batch_tasks)
        
        # Execute tasks in parallel
        job_group = group(tasks)
        result = job_group.apply_async()
        
        return {
            'job_id': str(job_id),
            'status': 'processing',
            'total_emails': len(emails),
            'message': 'Bulk verification started'
        }
        
    except VerificationJob.DoesNotExist:
        return {
            'job_id': str(job_id),
            'status': 'failed',
            'error': 'Job not found'
        }
    except Exception as e:
        # Update job status to failed
        try:
            job = VerificationJob.objects.get(job_id=job_id)
            job.status = 'failed'
            job.error_message = str(e)
            job.save()
        except:
            pass
        
        return {
            'job_id': str(job_id),
            'status': 'failed',
            'error': str(e)
        }


@shared_task
def cleanup_old_jobs(days=30):
    """
    Cleanup old verification jobs and results.
    Run this periodically to keep the database clean.
    """
    from datetime import timedelta
    
    cutoff_date = timezone.now() - timedelta(days=days)
    
    # Delete old jobs (this will cascade to EmailResults)
    deleted_count = VerificationJob.objects.filter(
        created_at__lt=cutoff_date,
        status__in=['completed', 'failed']
    ).delete()
    
    return {
        'deleted_jobs': deleted_count[0],
        'cutoff_date': cutoff_date.isoformat()
    }
