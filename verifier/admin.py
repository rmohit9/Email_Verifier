from django.contrib import admin
from .models import (
    VerificationJob, EmailResult, DisposableEmailDomain,
    EmailCampaign, CampaignRecipient, CampaignLog
)


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


@admin.register(DisposableEmailDomain)
class DisposableEmailDomainAdmin(admin.ModelAdmin):
    list_display = ['domain', 'is_active', 'added_at']
    list_filter = ['is_active', 'added_at']
    search_fields = ['domain']
    ordering = ['domain']


@admin.register(EmailCampaign)
class EmailCampaignAdmin(admin.ModelAdmin):
    list_display = ['campaign_id', 'subject', 'status', 'total_recipients', 
                    'sent_count', 'failed_count', 'progress_percentage', 'created_at', 'sent_at']
    list_filter = ['status', 'created_at', 'sent_at']
    search_fields = ['campaign_id', 'subject', 'user__username']
    readonly_fields = ['campaign_id', 'created_at', 'updated_at', 'sent_at']
    ordering = ['-created_at']
    
    fieldsets = (
        ('Campaign Info', {
            'fields': ('campaign_id', 'user', 'subject', 'csv_filename')
        }),
        ('Message', {
            'fields': ('message',)
        }),
        ('Delivery', {
            'classes': ('collapse',),
            'fields': (
                'sender_name', 'sender_email', 'reply_to',
                'batch_size', 'delay_between_batches', 'schedule_at', 'tags',
                'enable_open_tracking', 'enable_click_tracking'
            )
        }),
        ('Statistics', {
            'fields': ('total_recipients', 'sent_count', 'failed_count', 'skipped_count', 'progress_percentage')
        }),
        ('Status', {
            'fields': ('status', 'error_message')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at', 'sent_at')
        }),
    )


@admin.register(CampaignRecipient)
class CampaignRecipientAdmin(admin.ModelAdmin):
    list_display = ['email', 'campaign', 'status', 'sent_at', 'brevo_message_id']
    list_filter = ['status', 'campaign', 'created_at', 'sent_at']
    search_fields = ['email', 'campaign__subject', 'brevo_message_id']
    readonly_fields = ['created_at', 'sent_at', 'brevo_message_id']
    ordering = ['-created_at']


@admin.register(CampaignLog)
class CampaignLogAdmin(admin.ModelAdmin):
    list_display = ['level', 'campaign', 'message', 'recipient', 'created_at']
    list_filter = ['level', 'campaign', 'created_at']
    search_fields = ['message', 'campaign__subject', 'recipient__email']
    readonly_fields = ['created_at']
    ordering = ['-created_at']



