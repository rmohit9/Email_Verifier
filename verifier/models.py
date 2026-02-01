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

class EmailCampaign(models.Model):
    """
    Tracks bulk email campaign uploads and sending
    """
    STATUS_CHOICES = [
        ('draft', 'Draft'),
        ('scheduled', 'Scheduled'),
        ('sending', 'Sending'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    ]
    
    campaign_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='campaigns')
    subject = models.CharField(max_length=255)
    message = models.TextField()
    csv_filename = models.CharField(max_length=255, blank=True, null=True)
    # Optional delivery / Brevo settings (left empty for admin to fill later)
    sender_name = models.CharField(max_length=255, blank=True, null=True)
    sender_email = models.EmailField(max_length=255, blank=True, null=True)
    reply_to = models.EmailField(max_length=255, blank=True, null=True)
    # Batch & rate limiting (defaults that can be overridden per campaign)
    batch_size = models.IntegerField(default=50)
    delay_between_batches = models.FloatField(default=1.0)
    # Scheduling and tags
    schedule_at = models.DateTimeField(null=True, blank=True)
    tags = models.JSONField(default=list, blank=True)
    # Tracking toggles
    enable_open_tracking = models.BooleanField(default=True)
    enable_click_tracking = models.BooleanField(default=True)
    
    total_recipients = models.IntegerField(default=0)
    sent_count = models.IntegerField(default=0)
    failed_count = models.IntegerField(default=0)
    skipped_count = models.IntegerField(default=0)  # duplicates, invalid emails
    
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='draft')
    progress_percentage = models.FloatField(default=0.0)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    sent_at = models.DateTimeField(null=True, blank=True)
    error_message = models.TextField(blank=True, null=True)
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', 'created_at']),
            models.Index(fields=['status', 'created_at']),
        ]
    
    def __str__(self):
        return f"Campaign {self.campaign_id} - {self.subject}"
    
    def update_progress(self):
        """Calculate and update progress percentage and persist counts"""
        if self.total_recipients > 0:
            self.progress_percentage = ((self.sent_count + self.failed_count) / self.total_recipients) * 100
        else:
            self.progress_percentage = 0.0
        # Ensure sent/failed counts and progress are persisted together
        self.save(update_fields=['progress_percentage', 'sent_count', 'failed_count', 'updated_at'])


class CampaignRecipient(models.Model):
    """
    Stores individual recipients for a campaign
    """
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('sent', 'Sent'),
        ('failed', 'Failed'),
        ('skipped', 'Skipped'),  # duplicate or invalid
    ]
    
    id = models.AutoField(primary_key=True)
    campaign = models.ForeignKey(EmailCampaign, on_delete=models.CASCADE, related_name='recipients')
    email = models.EmailField(max_length=255)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    
    # Tracking
    sent_at = models.DateTimeField(null=True, blank=True)
    brevo_message_id = models.CharField(max_length=255, blank=True, null=True)  # Brevo response ID
    error_message = models.TextField(blank=True, null=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['id']
        unique_together = [['campaign', 'email']]  # Prevent duplicates within a campaign
        indexes = [
            models.Index(fields=['campaign', 'status']),
            models.Index(fields=['email']),
        ]
    
    def __str__(self):
        return f"{self.email} - {self.status}"


class CampaignLog(models.Model):
    """
    Logs for campaign operations (sending, errors, etc.)
    """
    LOG_LEVEL_CHOICES = [
        ('info', 'Info'),
        ('warning', 'Warning'),
        ('error', 'Error'),
        ('success', 'Success'),
    ]
    
    id = models.AutoField(primary_key=True)
    campaign = models.ForeignKey(EmailCampaign, on_delete=models.CASCADE, related_name='logs')
    level = models.CharField(max_length=20, choices=LOG_LEVEL_CHOICES, default='info')
    message = models.TextField()
    recipient = models.ForeignKey(CampaignRecipient, on_delete=models.SET_NULL, null=True, blank=True, related_name='logs')
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['campaign', 'level']),
        ]
    
    def __str__(self):
        return f"[{self.level.upper()}] {self.message[:50]}"
