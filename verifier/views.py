from django.shortcuts import render
from django.template.loader import render_to_string
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt

from email_validator import validate_email, EmailNotValidError

import dns.resolver
import json
import re
from functools import lru_cache
from datetime import datetime, timedelta
import hashlib
import math


# ============================================================================
# VIEWS (unchanged)
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


# ============================================================================
# DNS & CORE VALIDATION (unchanged - perfect as is)
# ============================================================================

def get_resolver():
    """
    Creates a DNS resolver with strict timeouts and reliable nameservers.
    This prevents the server from hanging on bad domains during production.
    """
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ['8.8.8.8', '1.1.1.1'] 
    resolver.timeout = 2.0
    resolver.lifetime = 2.0
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
    Checks if the domain is registered and active on the internet using NS records.
    Uses strict timeouts.
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
    Uses strict timeouts.
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


# ============================================================================
# ADVANCED ALGORITHMIC DETECTION (NO KEYWORD LISTS)
# ============================================================================

@lru_cache(maxsize=1)
def get_trusted_providers():
    """Major email providers that are never disposable."""
    return {
        'gmail.com', 'googlemail.com', 'google.com',
        'outlook.com', 'hotmail.com', 'live.com', 'msn.com', 'outlook.in',
        'icloud.com', 'me.com', 'mac.com',
        'yahoo.com', 'yahoo.co.uk', 'yahoo.co.in', 'yahoo.fr', 'ymail.com',
        'protonmail.com', 'proton.me', 'pm.me', 'aol.com', 'zoho.com',
        'mail.com', 'gmx.com', 'gmx.net', 'yandex.com', 'yandex.ru',
        'fastmail.com', 'hey.com', 'tutanota.com', 'tuta.io', 'mail.ru'
    }

@lru_cache(maxsize=1)
def get_enterprise_mx_patterns():
    """MX patterns indicating legitimate enterprise email services."""
    return [
        r'aspmx.*\.l\.google\.com$', r'.*\.googlemail\.com$', r'smtp\.google\.com$',
        r'.*\.mail\.protection\.outlook\.com$', r'.*-mail\.protection\.outlook\.com$',
        r'.*\.pphosted\.com$', r'.*\.proofpoint\.com$',
        r'.*\.mimecast\.com$', r'.*\.mimecast-offshore\.com$',
        r'.*\.messagingengine\.com$', r'.*\.emailsrvr\.com$',
        r'mx.*\.zoho\.(com|eu|in)$', r'.*\.zohomail\.com$',
        r'.*\.mailgun\.org$', r'.*\.sendgrid\.net$',
        r'.*\.amazonses\.com$', r'.*\.smtp\.goog$'
    ]

@lru_cache(maxsize=1)
def get_high_risk_tlds():
    """TLDs with low barriers to entry (free/cheap) - commonly abused."""
    return {
        'tk', 'ml', 'ga', 'cf', 'gq',  # Freenom (completely free)
        'xyz', 'top', 'click', 'link', 'loan', 'win', 'bid', 'racing',
        'download', 'stream', 'trade', 'party', 'review', 'faith', 'science',
        'accountant', 'date', 'cricket', 'webcam', 'men', 'wang', 'zip'
    }


# ============================================================================
# MATHEMATICAL & LINGUISTIC ANALYSIS
# ============================================================================

def calculate_shannon_entropy(text):
    """
    Calculate true Shannon entropy - measures randomness/unpredictability.
    
    Higher entropy (>4.0) = random character distribution
    Lower entropy (<3.0) = patterned/meaningful text
    
    Returns: float (0-5+ typically)
    """
    if not text:
        return 0.0
    
    # Character frequency distribution
    freq = {}
    for char in text.lower():
        freq[char] = freq.get(char, 0) + 1
    
    # Shannon entropy calculation
    entropy = 0.0
    text_len = len(text)
    
    for count in freq.values():
        probability = count / text_len
        if probability > 0:
            entropy -= probability * math.log2(probability)
    
    return entropy


def calculate_pronounceability_score(text):
    """
    Measures how pronounceable/natural a domain name is.
    
    Real brands are pronounceable (google, amazon, microsoft)
    Random disposable domains are not (xkf3jd, qwzxc)
    
    Returns: (score, reason)
    - Lower score = more pronounceable = legitimate
    - Higher score = unpronounceable = suspicious
    """
    if not text or len(text) < 2:
        return 0, []
    
    text = text.lower()
    score = 0
    reasons = []
    
    vowels = set('aeiou')
    consonants = set('bcdfghjklmnpqrstvwxyz')
    
    # Count vowels and consonants
    vowel_count = sum(1 for c in text if c in vowels)
    consonant_count = sum(1 for c in text if c in consonants)
    alpha_count = vowel_count + consonant_count
    
    if alpha_count == 0:
        return 100, ["No alphabetic characters"]
    
    # 1. Vowel ratio analysis
    vowel_ratio = vowel_count / alpha_count
    
    # Natural language has ~40% vowels (English: 38-42%)
    if vowel_ratio < 0.15:
        score += 40
        reasons.append(f"Very few vowels ({vowel_ratio:.1%})")
    elif vowel_ratio > 0.65:
        score += 25
        reasons.append(f"Too many vowels ({vowel_ratio:.1%})")
    
    # No vowels at all in word > 3 chars = definitely random
    if vowel_count == 0 and alpha_count > 3:
        score += 50
        reasons.append("Zero vowels")
    
    # 2. Consonant cluster analysis
    max_consonant_run = 0
    current_run = 0
    
    for char in text:
        if char in consonants:
            current_run += 1
            max_consonant_run = max(max_consonant_run, current_run)
        else:
            current_run = 0
    
    # Natural words rarely have 4+ consonants in a row
    if max_consonant_run >= 5:
        score += 35
        reasons.append(f"{max_consonant_run} consonants in a row")
    elif max_consonant_run >= 4:
        score += 20
        reasons.append(f"{max_consonant_run} consonants in a row")
    
    # 3. Alternating vowel-consonant check (too perfect = suspicious)
    # Natural words have some clustering, not perfect alternation
    alternations = 0
    for i in range(len(text) - 1):
        curr_is_vowel = text[i] in vowels
        next_is_vowel = text[i + 1] in vowels
        if curr_is_vowel != next_is_vowel:
            alternations += 1
    
    if alternations == len(text) - 1 and len(text) > 5:
        score += 30
        reasons.append("Perfect alternating pattern (artificial)")
    
    # 4. Check for common letter combinations
    # Legitimate domains use common bigrams (th, er, on, an, etc.)
    common_bigrams = {
        'th', 'er', 'on', 'an', 'in', 'ed', 'nd', 'ha', 'at', 'en',
        'es', 'of', 'or', 'nt', 'ea', 'ti', 'to', 'it', 'st', 'io',
        'le', 'is', 'ou', 'ar', 're', 've', 'co', 'ly', 'ng', 'al'
    }
    
    bigrams = [text[i:i+2] for i in range(len(text)-1)]
    common_count = sum(1 for bg in bigrams if bg in common_bigrams)
    
    if len(bigrams) > 0:
        common_ratio = common_count / len(bigrams)
        
        # Very few common bigrams = random generation
        if common_ratio < 0.1 and len(text) > 5:
            score += 25
            reasons.append(f"Rare letter combinations ({common_ratio:.1%})")
    
    return score, reasons


def analyze_character_diversity(text):
    """
    Analyzes character type distribution and patterns.
    
    Disposable domains often have specific patterns:
    - Heavy number usage
    - Mixed alphanumeric chaos
    - Repeating patterns
    
    Returns: (score, reasons)
    """
    if not text:
        return 0, []
    
    score = 0
    reasons = []
    
    # Character type counts
    alpha_count = sum(1 for c in text if c.isalpha())
    digit_count = sum(1 for c in text if c.isdigit())
    special_count = len(text) - alpha_count - digit_count
    
    # 1. Number dominance
    if digit_count > 0:
        digit_ratio = digit_count / len(text)
        
        if digit_ratio > 0.6:
            score += 40
            reasons.append(f"Mostly numbers ({digit_ratio:.0%})")
        elif digit_ratio > 0.4:
            score += 25
            reasons.append(f"Heavy number usage ({digit_ratio:.0%})")
        elif digit_count >= 5:
            score += 15
            reasons.append(f"{digit_count} numbers present")
    
    # 2. Hyphen/underscore patterns
    hyphen_count = text.count('-')
    underscore_count = text.count('_')
    
    if hyphen_count > 2:
        score += 20
        reasons.append(f"{hyphen_count} hyphens")
    
    if underscore_count > 0:
        score += 15
        reasons.append("Contains underscores")
    
    # 3. Repeating character patterns (aa, 11, etc.)
    repeats = re.findall(r'(.)\1{2,}', text)
    if repeats:
        score += 15 * len(repeats)
        reasons.append(f"Repeating characters: {len(repeats)}")
    
    # 4. Number clustering (multiple numbers together)
    number_clusters = re.findall(r'\d{3,}', text)
    if number_clusters:
        score += 10 * len(number_clusters)
        reasons.append(f"Number clusters: {number_clusters}")
    
    # 5. Mixed case in domain (domains are case-insensitive, so this is rare)
    # This check would need original case, skip for now
    
    return score, reasons


def analyze_length_characteristics(domain_parts):
    """
    Analyzes length patterns across domain components.
    
    Legitimate domains tend to have:
    - Reasonable lengths (5-15 chars for main part)
    - Balanced structure
    
    Disposable domains often have:
    - Very short (1-3 chars) or very long (20+) names
    - Unbalanced subdomain structures
    
    Returns: (score, reasons)
    """
    if len(domain_parts) < 2:
        return 0, []
    
    score = 0
    reasons = []
    
    # Extract parts (excluding TLD)
    main_parts = domain_parts[:-1]
    primary_name = main_parts[-1]  # The actual domain name
    
    # 1. Primary domain length analysis
    primary_len = len(primary_name)
    
    if primary_len <= 2:
        score += 30
        reasons.append(f"Extremely short domain ({primary_len} chars)")
    elif primary_len == 3:
        score += 15
        reasons.append(f"Very short domain ({primary_len} chars)")
    elif primary_len >= 25:
        score += 35
        reasons.append(f"Extremely long domain ({primary_len} chars)")
    elif primary_len >= 18:
        score += 20
        reasons.append(f"Very long domain ({primary_len} chars)")
    
    # 2. Subdomain analysis
    if len(main_parts) > 1:
        subdomain = main_parts[0]
        subdomain_len = len(subdomain)
        
        # Long random-looking subdomains
        if subdomain_len > 12:
            score += 20
            reasons.append(f"Long subdomain ({subdomain_len} chars)")
        
        # Very short subdomains (often user IDs)
        if subdomain_len <= 2:
            score += 10
            reasons.append(f"Very short subdomain")
        
        # Multiple subdomains (e.g., a.b.c.domain.com)
        if len(main_parts) > 2:
            score += 15
            reasons.append(f"{len(main_parts)} domain levels")
    
    # 3. Total domain length (without TLD)
    total_len = sum(len(part) for part in main_parts)
    
    if total_len > 40:
        score += 25
        reasons.append(f"Very long total domain ({total_len} chars)")
    
    return score, reasons


# ============================================================================
# MX RECORD INTELLIGENCE
# ============================================================================

def analyze_mx_records(mx_records):
    """
    Deep MX analysis using behavioral patterns, not keywords.
    
    Legitimate providers:
    - Use established infrastructure
    - Have redundant MX servers
    - Follow naming conventions
    
    Disposable services:
    - Often self-hosted
    - Single MX record
    - Generic/simple MX names
    
    Returns: (score, reasons)
    """
    if not mx_records:
        return 0, []
    
    reasons = []
    score = 0
    
    enterprise_patterns = get_enterprise_mx_patterns()
    
    # 1. Enterprise provider detection (strong legitimacy signal)
    for mx in mx_records:
        mx_lower = mx.lower()
        for pattern in enterprise_patterns:
            if re.match(pattern, mx_lower):
                return -60, [f"Enterprise email infrastructure: {mx}"]
    
    # 2. MX record count analysis
    mx_count = len(mx_records)
    
    if mx_count == 1:
        score += 25
        reasons.append("Single MX record (no redundancy)")
    elif mx_count >= 3:
        score -= 15
        reasons.append(f"{mx_count} MX records (good redundancy)")
    
    # 3. Self-referential MX (domain's MX points to itself)
    if mx_count == 1:
        mx = mx_records[0].lower()
        mx_parts = mx.split('.')
        
        # Check if MX is just "mail.domain.com" or "domain.com"
        if len(mx_parts) >= 2:
            mx_domain = '.'.join(mx_parts[-2:])
            
            # This is a self-hosted indicator
            # Not necessarily bad, but common for disposable services
            if len(mx_parts) <= 3:  # mail.domain.com or domain.com
                score += 15
                reasons.append("Self-hosted MX configuration")
    
    # 4. Generic MX naming patterns (algorithmic detection)
    for mx in mx_records:
        mx_lower = mx.lower()
        hostname = mx_lower.split('.')[0]
        
        # Pattern: just "mx" or "mx" + single digit
        if re.match(r'^mx\d?$', hostname):
            score += 10
            reasons.append(f"Generic MX name: {hostname}")
            break
        
        # Pattern: just "mail" or "mail" + single digit
        if re.match(r'^mail\d?$', hostname):
            score += 8
            reasons.append(f"Generic MX name: {hostname}")
            break
        
        # Pattern: just "smtp" + optional digit
        if re.match(r'^smtp\d?$', hostname):
            score += 10
            reasons.append(f"Generic MX name: {hostname}")
            break
    
    # 5. MX complexity analysis (legitimate providers have complex infrastructure)
    for mx in mx_records:
        mx_parts = mx.lower().split('.')
        
        # Very short MX hostnames (< 4 chars) are often generic
        if len(mx_parts[0]) < 4 and mx_parts[0] not in ['mx', 'mail', 'smtp']:
            score += 12
            reasons.append(f"Very short MX hostname: {mx_parts[0]}")
        
        # Very complex/long MX names often indicate enterprise
        if len(mx_parts) > 4:
            score -= 10
            reasons.append("Complex MX structure (enterprise indicator)")
            break
    
    # 6. MX priority analysis (if we had priority data)
    # Legitimate services often have proper failover with different priorities
    # This would require storing MX priorities from DNS response
    
    return score, reasons


def analyze_dns_infrastructure(domain, mx_records):
    """
    Analyzes overall DNS setup quality.
    
    Established domains have:
    - Professional DNS configuration
    - Multiple nameservers
    - Proper redundancy
    
    Returns: (score, reasons)
    """
    score = 0
    reasons = []
    
    # 1. Check nameserver diversity (requires additional DNS lookup)
    try:
        resolver = get_resolver()
        ns_records = resolver.resolve(domain, 'NS')
        ns_count = len(ns_records)
        
        if ns_count >= 3:
            score -= 10
            reasons.append(f"{ns_count} nameservers (good infrastructure)")
        elif ns_count == 1:
            score += 15
            reasons.append("Single nameserver (minimal setup)")
    except:
        pass
    
    # 2. MX-Domain relationship
    if mx_records:
        # Check if MX servers are on completely different domains (CDN/provider)
        different_domain_count = 0
        
        for mx in mx_records:
            mx_parts = mx.lower().split('.')
            if len(mx_parts) >= 2:
                mx_domain = '.'.join(mx_parts[-2:])
                domain_parts = domain.lower().split('.')
                if len(domain_parts) >= 2:
                    email_domain = '.'.join(domain_parts[-2:])
                    
                    if mx_domain != email_domain:
                        different_domain_count += 1
        
        # All MX on different domains = using email provider (good sign)
        if different_domain_count == len(mx_records) and len(mx_records) > 0:
            score -= 15
            reasons.append("External email provider (professional setup)")
    
    return score, reasons


# ============================================================================
# TLD RISK ANALYSIS
# ============================================================================

def analyze_tld_risk(tld):
    """
    TLD analysis based on cost and abuse potential.
    
    Returns: (score, reasons)
    """
    score = 0
    reasons = []
    
    high_risk = get_high_risk_tlds()
    
    # Free/extremely cheap TLDs
    if tld in high_risk:
        score += 35
        reasons.append(f"High-risk TLD: .{tld}")
        return score, reasons
    
    # Premium TLDs (cost barrier = less abuse)
    premium_tlds = {'com', 'net', 'org', 'io', 'co', 'ai', 'app', 'dev'}
    if tld in premium_tlds:
        score -= 5
        reasons.append(f"Premium TLD: .{tld}")
    
    # Geographic TLDs (often legitimate local businesses)
    geo_tlds = {
        'us', 'uk', 'ca', 'au', 'de', 'fr', 'jp', 'in', 'br', 'mx',
        'nl', 'se', 'no', 'dk', 'fi', 'es', 'it', 'ch', 'at', 'be'
    }
    if tld in geo_tlds:
        score -= 3
        reasons.append(f"Geographic TLD: .{tld}")
    
    # Education/Government (highly trusted)
    if tld in {'edu', 'gov', 'mil'}:
        score -= 50
        reasons.append(f"Institutional TLD: .{tld}")
    
    return score, reasons


# ============================================================================
# MAIN VALIDATION FUNCTION
# ============================================================================

def check_email_comprehensive(email, strict_mode=False):
    """
    Production-grade email validation using pure algorithmic analysis.
    
    NO KEYWORD MATCHING - Uses mathematical and behavioral patterns:
    - Shannon entropy (randomness)
    - Pronounceability scoring (linguistic analysis)
    - Character diversity patterns
    - DNS infrastructure quality
    - MX configuration analysis
    - Length pattern analysis
    - TLD risk assessment
    
    Scoring System:
    - Score < 0: Highly trusted (enterprise/institutional)
    - Score 0-40: Legitimate
    - Score 40-70: Suspicious (allowed in non-strict)
    - Score 70-100: Likely disposable (blocked in strict)
    - Score >= 100: Definitely disposable (always blocked)
    
    Args:
        email: Email address to validate
        strict_mode: If True, block score >= 70; if False, block >= 100
    
    Returns:
        {
            'valid': bool,
            'is_disposable': bool,
            'confidence': str,
            'score': int,
            'reasons': list,
            'details': dict
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
    
    # ========================================================================
    # PHASE 1: SYNTAX VALIDATION
    # ========================================================================
    syntax_check = verify_syntax(email)
    result['details']['syntax'] = syntax_check
    
    if not syntax_check['valid']:
        result['reasons'].append(syntax_check['reason'])
        result['score'] = 100
        result['is_disposable'] = True
        return result
    
    domain = syntax_check['domain']
    
    # ========================================================================
    # PHASE 2: WHITELIST CHECK (Trusted Providers)
    # ========================================================================
    if domain in get_trusted_providers():
        result['valid'] = True
        result['is_disposable'] = False
        result['confidence'] = 'high'
        result['score'] = -100
        result['reasons'].append(f"Trusted provider: {domain}")
        return result
    
    # ========================================================================
    # PHASE 3: DNS VALIDATION
    # ========================================================================
    domain_check = verify_domain(domain)
    result['details']['domain'] = domain_check
    
    if not domain_check['valid']:
        result['reasons'].append(domain_check['reason'])
        result['score'] = 100
        result['is_disposable'] = True
        return result
    
    mx_check = verify_mx(domain)
    result['details']['mx'] = mx_check
    
    if not mx_check['valid']:
        result['reasons'].append(mx_check['reason'])
        result['score'] = 95
        result['is_disposable'] = True
        return result
    
    # ========================================================================
    # PHASE 4: ALGORITHMIC ANALYSIS (No keyword matching)
    # ========================================================================
    
    mx_records = mx_check.get('mx_records', [])
    domain_parts = domain.split('.')
    
    if len(domain_parts) < 2:
        result['score'] = 100
        result['is_disposable'] = True
        result['reasons'].append("Invalid domain structure")
        return result
    
    domain_name = domain_parts[-2]  # Main domain name (excluding TLD)
    tld = domain_parts[-1]
    
    # --- 1. MX Record Analysis ---
    mx_score, mx_reasons = analyze_mx_records(mx_records)
    result['score'] += mx_score
    result['reasons'].extend(mx_reasons)
    
    # Enterprise provider detected - high trust
    if mx_score < -50:
        result['valid'] = True
        result['is_disposable'] = False
        result['confidence'] = 'high'
        return result
    
    # --- 2. TLD Risk Analysis ---
    tld_score, tld_reasons = analyze_tld_risk(tld)
    result['score'] += tld_score
    result['reasons'].extend(tld_reasons)
    
    # Institutional domain - high trust
    if tld_score < -40:
        result['valid'] = True
        result['is_disposable'] = False
        result['confidence'] = 'high'
        return result
    
    # --- 3. Shannon Entropy (Randomness) ---
    entropy = calculate_shannon_entropy(domain_name)
    result['details']['entropy'] = entropy
    
    if entropy > 4.2:
        score_add = 40
        result['score'] += score_add
        result['reasons'].append(f"Very high entropy ({entropy:.2f}) - random characters")
    elif entropy > 3.8:
        score_add = 25
        result['score'] += score_add
        result['reasons'].append(f"High entropy ({entropy:.2f}) - likely random")
    elif entropy < 2.5:
        result['score'] -= 5
        result['reasons'].append(f"Low entropy ({entropy:.2f}) - patterned/meaningful")
    
    # --- 4. Pronounceability Analysis ---
    pronounce_score, pronounce_reasons = calculate_pronounceability_score(domain_name)
    result['score'] += pronounce_score
    result['reasons'].extend(pronounce_reasons)
    
    # --- 5. Character Diversity ---
    diversity_score, diversity_reasons = analyze_character_diversity(domain_name)
    result['score'] += diversity_score
    result['reasons'].extend(diversity_reasons)
    
    # --- 6. Length Characteristics ---
    length_score, length_reasons = analyze_length_characteristics(domain_parts)
    result['score'] += length_score
    result['reasons'].extend(length_reasons)
    
    # --- 7. DNS Infrastructure Quality ---
    dns_score, dns_reasons = analyze_dns_infrastructure(domain, mx_records)
    result['score'] += dns_score
    result['reasons'].extend(dns_reasons)
    
    # ========================================================================
    # PHASE 5: FINAL DECISION
    # ========================================================================
    
    final_score = result['score']
    
    # Definite disposable
    if final_score >= 100:
        result['valid'] = False
        result['is_disposable'] = True
        result['confidence'] = 'high'
    
    # Likely disposable (strict mode blocks)
    elif final_score >= 70:
        if strict_mode:
            result['valid'] = False
            result['is_disposable'] = True
            result['confidence'] = 'high'
        else:
            result['valid'] = True
            result['is_disposable'] = False
            result['confidence'] = 'medium'
            result['reasons'].append("Suspicious patterns but allowed in non-strict mode")
    
    # Suspicious but allowed
    elif final_score >= 40:
        result['valid'] = True
        result['is_disposable'] = False
        result['confidence'] = 'medium'
        result['reasons'].append("Some unusual patterns detected")
    
    # Legitimate
    else:
        result['valid'] = True
        result['is_disposable'] = False
        result['confidence'] = 'high' if final_score < 20 else 'medium-high'
    
    return result


def is_disposable_email(email, strict_mode=False):
    """
    Simple boolean check for disposable email detection.
    
    Args:
        email: Email address to check
        strict_mode: If True, flag medium-confidence disposable (score >= 70)
    
    Returns:
        bool: True if disposable, False otherwise
    """
    result = check_email_comprehensive(email, strict_mode)
    return result['is_disposable']


# ============================================================================
# BATCH PROCESSING FOR PRODUCTION (10,000+ emails)
# ============================================================================

def batch_verify_emails(emails, strict_mode=False, max_workers=10):
    """
    Efficiently process large batches of emails using concurrent processing.
    
    Args:
        emails: List of email addresses
        strict_mode: Strict validation mode
        max_workers: Number of concurrent workers (default: 10)
    
    Returns:
        dict: {email: result_dict}
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed
    
    results = {}
    
    def process_single(email):
        return email, check_email_comprehensive(email, strict_mode)
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(process_single, email): email for email in emails}
        
        for future in as_completed(futures):
            email, result = future.result()
            results[email] = result
    
    return results