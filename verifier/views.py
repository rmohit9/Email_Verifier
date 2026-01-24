from django.shortcuts import render
from django.template.loader import render_to_string
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt

from email_validator import validate_email, EmailNotValidError

import dns.resolver
import json

import re
from functools import lru_cache


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



#TLD risk scoring (.tk, .xyz = high risk)
#Keyword detection ("temp", "disposable", "trash")
#Pattern analysis (random strings, excessive numbers/hyphens)
#Enterprise provider detection (Google Workspace MX = bonus trust)


# ----------------------------------------------------------------------------
# Permanent Heuristics (No updates needed)
# ----------------------------------------------------------------------------

@lru_cache(maxsize=1)
def get_trusted_providers():
    """Major email providers that are never disposable."""
    return {
        # Google
        'gmail.com', 'googlemail.com', 'google.com',
        # Microsoft
        'outlook.com', 'hotmail.com', 'live.com', 'msn.com', 'outlook.in',
        # Apple
        'icloud.com', 'me.com', 'mac.com',
        # Yahoo
        'yahoo.com', 'yahoo.co.uk', 'yahoo.co.in', 'yahoo.fr', 'ymail.com',
        # Other major providers
        'protonmail.com', 'proton.me', 'pm.me', 'aol.com', 'zoho.com',
        'mail.com', 'gmx.com', 'gmx.net', 'yandex.com', 'yandex.ru',
        'fastmail.com', 'hey.com', 'tutanota.com', 'tuta.io', 'mail.ru'
    }

@lru_cache(maxsize=1)
def get_enterprise_mx_patterns():
    """MX patterns that indicate legitimate enterprise email services."""
    return [
        # Google Workspace
        r'.*\.google\.com$', r'.*\.googlemail\.com$', r'aspmx.*\.l\.google\.com$',
        # Microsoft 365
        r'.*\.outlook\.com$', r'.*\.protection\.outlook\.com$', r'.*-mail\.protection\.outlook\.com$',
        # Proofpoint (enterprise security)
        r'.*\.pphosted\.com$', r'.*\.proofpoint\.com$',
        # Mimecast (enterprise security)
        r'.*\.mimecast\.com$',
        # Enterprise providers
        r'.*\.messagingengine\.com$',  # FastMail
        r'.*\.emailsrvr\.com$',  # Rackspace
        r'mx\.zoho\.com$', r'.*\.zoho\.com$',
    ]

@lru_cache(maxsize=1)
def get_high_risk_tlds():
    """TLDs commonly used by disposable services."""
    return {
        # Free TLDs
        'tk', 'ml', 'ga', 'cf', 'gq',
        # Cheap/spam-prone TLDs
        'xyz', 'top', 'click', 'link', 'loan', 'win', 'bid', 'racing',
        'download', 'stream', 'trade', 'party', 'review', 'faith', 'science',
        'accountant', 'date', 'cricket', 'webcam', 'men', 'wang'
    }

@lru_cache(maxsize=1)
def get_disposable_keywords():
    """Keywords that appear in disposable service domain names."""
    return {
        'temp', 'temporary', 'disposable', 'throwaway', 'trash', 'fake',
        'guerrilla', 'burner', 'spam', 'jetable', 'wegwerf',
        '10minute', 'minute', 'hour', 'maildrop', 'mailinator',
        'getnada', 'mohmal', 'sharklasers'
    }

@lru_cache(maxsize=1)
def load_disposable_blacklist():
    """Load existing disposable domains blacklist."""
    file_path = BASE_DIR / "utils" / "disposable_domains.txt"
    domains = set()
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                domain = line.strip().lower()
                if domain and not domain.startswith("#"):
                    domains.add(domain)
    except FileNotFoundError:
        pass
    return domains


# ----------------------------------------------------------------------------
# Analysis Functions
# ----------------------------------------------------------------------------

def analyze_mx_records(mx_records):
    """
    Analyzes MX records to determine if they point to legitimate providers.
    Returns: (score, reason)
    - Negative score = legitimate (enterprise provider)
    - Zero = standard configuration
    """
    if not mx_records:
        return 0, None
    
    enterprise_patterns = get_enterprise_mx_patterns()
    
    for mx in mx_records:
        mx_lower = mx.lower()
        
        # Check for enterprise email providers
        for pattern in enterprise_patterns:
            if re.match(pattern, mx_lower):
                return -50, f"Enterprise provider detected: {mx}"
    
    return 0, None

def analyze_domain_structure(domain):
    """
    Analyzes domain characteristics for disposable indicators.
    Returns: (score, reasons)
    """
    score = 0
    reasons = []
    
    parts = domain.split('.')
    if len(parts) < 2:
        return 100, ["Invalid domain structure"]
    
    domain_name = parts[0]
    tld = parts[-1]
    
    # 1. High-risk TLD
    if tld in get_high_risk_tlds():
        score += 40
        reasons.append(f"High-risk TLD: .{tld}")
    
    # 2. Disposable keywords in domain
    keywords = get_disposable_keywords()
    for keyword in keywords:
        if keyword in domain_name.lower():
            score += 60
            reasons.append(f"Disposable keyword: '{keyword}'")
            break
    
    # 3. Very short domain (< 4 characters)
    if len(domain_name) < 4:
        score += 25
        reasons.append(f"Very short domain: {len(domain_name)} chars")
    
    # 4. Excessive hyphens (random-looking)
    hyphen_count = domain_name.count('-')
    if hyphen_count > 2:
        score += 20
        reasons.append(f"Many hyphens: {hyphen_count}")
    
    # 5. Mostly numbers (random-generated domains)
    num_count = sum(c.isdigit() for c in domain_name)
    if num_count > len(domain_name) * 0.6:
        score += 30
        reasons.append(f"Mostly numbers: {num_count}/{len(domain_name)}")
    
    # 6. Long strings of consonants (random domains)
    if re.search(r'[bcdfghjklmnpqrstvwxyz]{5,}', domain_name, re.IGNORECASE):
        score += 25
        reasons.append("Random consonant sequence detected")
    
    # 7. Number + letter combinations without vowels
    if re.search(r'\d[^aeiou\d]{2,}|\d.*\d', domain_name, re.IGNORECASE) and not re.search(r'[aeiou]', domain_name, re.IGNORECASE):
        score += 30
        reasons.append("Suspicious number-letter pattern")
    
    return score, reasons


# ----------------------------------------------------------------------------
# Main Validation Functions
# ----------------------------------------------------------------------------

def check_email_comprehensive(email, strict_mode=False):
    """
    Comprehensive email validation with scoring system.
    Uses existing verify_* functions + new heuristics.
    
    Flow:
    1. Syntax check (existing verify_syntax)
    2. Whitelist check (skip all other checks if trusted)
    3. Blacklist check (skip all other checks if known disposable)
    4. Domain + MX check (existing verify_domain + verify_mx)
    5. Only if DNS passed: Add MX analysis + domain structure scoring
    
    Args:
        email: Email address to validate
        strict_mode: If True, block medium-confidence disposable emails (score >= 50)
                     If False, only block high-confidence disposable (score >= 80)
    
    Returns:
        {
            'valid': bool,           # Overall validity
            'is_disposable': bool,   # Disposable email detected
            'confidence': str,       # 'high', 'medium', 'low'
            'score': int,            # Suspicion score (higher = more suspicious)
            'reasons': list,         # Detailed reasons
            'details': dict          # Sub-check results
        }
    """
    result = {
        'valid': False,
        'is_disposable': False,
        'confidence': 'high',
        'score': 0,
        'reasons': [],
        'details': {}
    }
    
    # Step 1: Syntax validation (existing function)
    syntax_check = verify_syntax(email)
    result['details']['syntax'] = syntax_check
    
    if not syntax_check['valid']:
        result['reasons'].append(syntax_check['reason'])
        return result
    
    domain = syntax_check['domain']
    
    # Step 2: Whitelist check (trusted providers)
    if domain in get_trusted_providers():
        result['valid'] = True
        result['is_disposable'] = False
        result['confidence'] = 'high'
        result['score'] = -100
        result['reasons'].append(f"Trusted provider: {domain}")
        return result
    
    # Step 3: Blacklist check (existing disposable list)
    blacklist = load_disposable_blacklist()
    if domain in blacklist or any(domain.endswith('.' + d) for d in blacklist):
        result['valid'] = False
        result['is_disposable'] = True
        result['confidence'] = 'high'
        result['score'] = 100
        result['reasons'].append("Domain in disposable blacklist")
        return result
    
    # Step 4: Domain existence check (existing function)
    domain_check = verify_domain(domain)
    result['details']['domain'] = domain_check
    
    if not domain_check['valid']:
        result['reasons'].append(domain_check['reason'])
        result['score'] = 100
        result['is_disposable'] = True
        return result
    
    # Step 5: MX record check (existing function)
    mx_check = verify_mx(domain)
    result['details']['mx'] = mx_check
    
    if not mx_check['valid']:
        result['reasons'].append(mx_check['reason'])
        result['score'] = 90
        result['is_disposable'] = True
        return result
    
    # ========================================================================
    # DNS checks passed - Now apply ADDITIONAL heuristics
    # ========================================================================
    
    # Step 6: Analyze MX records for enterprise providers
    mx_score, mx_reason = analyze_mx_records(mx_check.get('mx_records', []))
    result['score'] += mx_score
    if mx_reason:
        result['reasons'].append(mx_reason)
    
    # If enterprise MX detected, email is valid
    if mx_score < 0:
        result['valid'] = True
        result['is_disposable'] = False
        result['confidence'] = 'high'
        return result
    
    # Step 7: Domain structure analysis
    structure_score, structure_reasons = analyze_domain_structure(domain)
    result['score'] += structure_score
    result['reasons'].extend(structure_reasons)
    
    # Step 8: Final determination
    if result['score'] >= 80:
        result['valid'] = False
        result['is_disposable'] = True
        result['confidence'] = 'high'
    elif result['score'] >= 50:
        if strict_mode:
            result['valid'] = False
            result['is_disposable'] = True
            result['confidence'] = 'medium'
        else:
            result['valid'] = True
            result['is_disposable'] = False
            result['confidence'] = 'medium'
            result['reasons'].append("Potentially suspicious but allowed in non-strict mode")
    else:
        result['valid'] = True
        result['is_disposable'] = False
        result['confidence'] = 'high' if result['score'] < 20 else 'medium'
    
    return result


def is_disposable_email(email, strict_mode=False):
    """
    Simple boolean check for disposable email.
    
    Args:
        email: Email address to check
        strict_mode: If True, flag medium-confidence disposable emails (score >= 50)
    
    Returns:
        bool: True if disposable, False otherwise
    """
    result = check_email_comprehensive(email, strict_mode)
    return result['is_disposable']