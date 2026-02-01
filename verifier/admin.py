from django.contrib import admin
from .models import VerificationJob, EmailResult

@admin.register(VerificationJob)
class VerificationJobAdmin(admin.ModelAdmin):
    list_display = ['job_id', 'filename', 'status', 'total_count', 'processed_count', 
                    'valid_count', 'invalid_count', 'disposable_count', 'progress_percentage', 'created_at']
    list_filter = ['status', 'created_at']
    search_fields = ['job_id', 'filename']
    readonly_fields = ['job_id', 'created_at', 'updated_at', 'completed_at']
    ordering = ['-created_at']

@admin.register(EmailResult)
class EmailResultAdmin(admin.ModelAdmin):
    # Matches the new 6-Step Pipeline fields
    list_display = [
        'email', 'status', 'domain', 
        'syntax_valid', 'domain_exists', 'mx_records_found', 
        'is_disposable', 'is_role_account', 'is_free_email', 'has_dns_security', 
        'verified_at'
    ]
    
    list_filter = [
        'status', 
        'syntax_valid', 'domain_exists', 'mx_records_found', 
        'is_disposable', 'is_role_account', 'is_free_email', 'has_dns_security'
    ]
    
    search_fields = ['email', 'domain', 'normalized_email']
    readonly_fields = ['verified_at']
    ordering = ['-verified_at']