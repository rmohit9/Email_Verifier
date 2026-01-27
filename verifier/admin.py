from django.contrib import admin
from .models import VerificationJob, EmailResult, DisposableEmailDomain


@admin.register(VerificationJob)
class VerificationJobAdmin(admin.ModelAdmin):
    list_display = ['job_id', 'filename', 'status', 'total_count', 'processed_count', 
                    'valid_count', 'invalid_count', 'progress_percentage', 'created_at']
    list_filter = ['status', 'created_at']
    search_fields = ['job_id', 'filename']
    readonly_fields = ['job_id', 'created_at', 'updated_at', 'completed_at']
    ordering = ['-created_at']


@admin.register(EmailResult)
class EmailResultAdmin(admin.ModelAdmin):
    list_display = ['email', 'status', 'domain', 'syntax_valid', 'domain_exists', 
                    'mx_records_found', 'smtp_valid', 'is_disposable', 'verified_at']
    list_filter = ['status', 'syntax_valid', 'domain_exists', 'mx_records_found', 
                   'smtp_valid', 'is_disposable', 'is_catch_all']
    search_fields = ['email', 'domain', 'normalized_email']
    readonly_fields = ['verified_at']
    ordering = ['-verified_at']


@admin.register(DisposableEmailDomain)
class DisposableEmailDomainAdmin(admin.ModelAdmin):
    list_display = ['domain', 'is_active', 'added_at']
    list_filter = ['is_active', 'added_at']
    search_fields = ['domain']
    ordering = ['domain']

