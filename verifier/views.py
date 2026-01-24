from django.shortcuts import render
from django.template.loader import render_to_string
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt

from email_validator import validate_email, EmailNotValidError

import dns.resolver
import json

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


def get_resolver():
    """
    Creates a DNS resolver with strict timeouts and reliable nameservers.
    This prevents the server from hanging on bad domains during production.
    """
    resolver = dns.resolver.Resolver()
    # Use Google and Cloudflare to ensure we get answers even if local DNS is slow
    resolver.nameservers = ['8.8.8.8', '1.1.1.1'] 
    # Fail fast: Don't wait 30s for a dead domain, 2s is enough.
    resolver.timeout = 2.0
    resolver.lifetime = 2.0
    
    return resolver

def verify_syntax(email):
    """
    Checks if the email follows valid formatting rules (Regex).
    Does NOT connect to the internet.
    """
    try:
        # check_deliverability=False means strict regex only
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
    Checks if the domain is registered and active on the internet using NS records.
    Uses strict timeouts.
    """
    if not domain:
        return {"valid": False, "reason": "No domain provided"}

    try:
        resolver = get_resolver()
        # Check for Name Server (NS) records to confirm domain is registered
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
    Uses strict timeouts.
    """
    try:
        resolver = get_resolver()
        answers = resolver.resolve(domain, 'MX')
        
        # Sort and clean the results
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
