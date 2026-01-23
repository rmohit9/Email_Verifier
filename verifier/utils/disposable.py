# Disposable Email Checker Logic (WIP)
# verifier/utils/disposable.py
# Just need to autoupdate the blacklisted domains

from functools import lru_cache
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

@lru_cache(maxsize=1)
def load_disposable_domains() -> set[str]:
    """
    Load disposable domains into memory once.
    Cached for performance.
    """
    file_path = BASE_DIR / "disposable_domains.txt"

    domains = set()
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                domain = line.strip().lower()
                if domain and not domain.startswith("#"):
                    domains.add(domain)
    except FileNotFoundError:
        pass  # fail-safe

    return domains


def normalize_domain(domain: str) -> str:
    """
    Normalize domain by removing subdomains.
    mail.tempdomain.com → tempdomain.com
    """
    parts = domain.split(".")
    if len(parts) > 2:
        return ".".join(parts[-2:])
    return domain


def is_disposable_email(email: str) -> bool:
    """
    Production-grade disposable email detection.
    """
    if not email or "@" not in email:
        return False

    domain = email.split("@")[-1].lower()
    normalized_domain = normalize_domain(domain)

    disposable_domains = load_disposable_domains()

    return (
        domain in disposable_domains
        or normalized_domain in disposable_domains
    )
