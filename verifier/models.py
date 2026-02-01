from django.db import models
from django.contrib.auth.models import User
import uuid

class VerificationJob(models.Model):
    """
    Tracks bulk email verification jobs
    """
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('processing', 'Processing'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    ]
    
    job_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    filename = models.CharField(max_length=255, blank=True, null=True)
    total_count = models.IntegerField(default=0)
    processed_count = models.IntegerField(default=0)
    valid_count = models.IntegerField(default=0)
    invalid_count = models.IntegerField(default=0)
    disposable_count = models.IntegerField(default=0)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    progress_percentage = models.FloatField(default=0.0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    error_message = models.TextField(blank=True, null=True)
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['status', 'created_at']),
            models.Index(fields=['user', 'created_at']),
        ]
    
    def __str__(self):
        return f"Job {self.job_id} - {self.status}"
    
    def update_progress(self):
        """Calculate and update progress percentage"""
        if self.total_count > 0:
            self.progress_percentage = (self.processed_count / self.total_count) * 100
        else:
            self.progress_percentage = 0.0
        self.save(update_fields=['progress_percentage', 'updated_at'])


class EmailResult(models.Model):
    """ Stores individual email verification results """
    STATUS_CHOICES = [
        ('valid', 'Valid'),
        ('invalid', 'Invalid'),
        ('disposable', 'Disposable'),
        ('risky', 'Risky'),
        ('unknown', 'Unknown'),
    ]
    
    id = models.AutoField(primary_key=True)
    job = models.ForeignKey(VerificationJob, on_delete=models.CASCADE, related_name='results')
    email = models.EmailField(max_length=255)
    
    # Status
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='unknown')
    
    # 1-5 Standard Checks
    syntax_valid = models.BooleanField(default=False)
    domain_exists = models.BooleanField(default=False)
    mx_records_found = models.BooleanField(default=False)
    is_disposable = models.BooleanField(default=False)
    
    # 6. Professional Enrichment (NEW)
    is_role_account = models.BooleanField(default=False)
    is_free_email = models.BooleanField(default=False)
    has_dns_security = models.BooleanField(default=False) # SPF/DMARC
    
    # Metadata
    reason = models.TextField(blank=True, null=True)
    mx_records = models.JSONField(default=list, blank=True)
    domain = models.CharField(max_length=255, blank=True, null=True)
    normalized_email = models.EmailField(max_length=255, blank=True, null=True)
    verified_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['id']
        indexes = [
            models.Index(fields=['job', 'status']),
            models.Index(fields=['email']),
            models.Index(fields=['status']),
        ]
    
    def __str__(self):
        return f"{self.email} - {self.status}"


class DisposableEmailDomain(models.Model):
    """
    List of disposable/temporary email domains
    """
    domain = models.CharField(max_length=255, unique=True, db_index=True)
    added_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)
    
    class Meta:
        ordering = ['domain']
    
    def __str__(self):
        return self.domain
