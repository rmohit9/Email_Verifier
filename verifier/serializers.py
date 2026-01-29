from rest_framework import serializers
from .models import VerificationJob, EmailResult, EmailCampaign, CampaignRecipient, CampaignLog
import csv
import io

class VerificationJobSerializer(serializers.ModelSerializer):
    # Add calculated fields for the UI cards
    disposable_count = serializers.SerializerMethodField()
    
    class Meta:
        model = VerificationJob
        fields = '__all__'
        read_only_fields = ['job_id', 'status', 'progress_percentage', 'created_at', 'completed_at', 'total_count', 'processed_count', 'valid_count', 'invalid_count', 'disposable_count','user']

    def get_disposable_count(self, obj):
        # Count results flagged as disposable
        return obj.results.filter(is_disposable=True).count()

class EmailResultSerializer(serializers.ModelSerializer):
    class Meta:
        model = EmailResult
        fields = '__all__'

class SingleVerifySerializer(serializers.Serializer):
    email = serializers.EmailField()

class BulkVerifySerializer(serializers.Serializer):
    emails = serializers.ListField(
        child=serializers.EmailField(),
        required=False
    )
    file = serializers.FileField(required=False)
    
    def validate(self, data):
        if not data.get('emails') and not data.get('file'):
            raise serializers.ValidationError("Either 'emails' list or 'file' upload is required.")
        return data


class CampaignRecipientSerializer(serializers.ModelSerializer):
    class Meta:
        model = CampaignRecipient
        fields = '__all__'
        read_only_fields = ['campaign', 'sent_at', 'brevo_message_id', 'created_at']


class CampaignLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = CampaignLog
        fields = '__all__'
        read_only_fields = ['campaign', 'created_at']


class EmailCampaignSerializer(serializers.ModelSerializer):
    recipients = CampaignRecipientSerializer(many=True, read_only=True)
    logs = CampaignLogSerializer(many=True, read_only=True)
    
    class Meta:
        model = EmailCampaign
        fields = '__all__'
        read_only_fields = ['campaign_id', 'user', 'status', 'progress_percentage', 'created_at', 'updated_at', 'sent_at', 'recipients', 'logs']


class EmailCampaignCreateSerializer(serializers.Serializer):
    """
    Serializer for creating a new email campaign from CSV upload
    """
    subject = serializers.CharField(max_length=255, required=True)
    message = serializers.CharField(required=True)
    csv_file = serializers.FileField(required=True)
    # Optional fields for later configuration
    sender_name = serializers.CharField(max_length=255, required=False, allow_blank=True)
    sender_email = serializers.EmailField(required=False, allow_null=True)
    reply_to = serializers.EmailField(required=False, allow_null=True)
    batch_size = serializers.IntegerField(required=False, min_value=1, default=50)
    delay_between_batches = serializers.FloatField(required=False, min_value=0.0, default=1.0)
    schedule_at = serializers.DateTimeField(required=False, allow_null=True)
    tags = serializers.ListField(child=serializers.CharField(), required=False)
    enable_open_tracking = serializers.BooleanField(required=False, default=True)
    enable_click_tracking = serializers.BooleanField(required=False, default=True)
    
    def validate_csv_file(self, value):
        """Validate CSV file structure and content"""
        if not value.name.endswith('.csv'):
            raise serializers.ValidationError("File must be a CSV file (.csv)")
        
        if value.size > 5 * 1024 * 1024:  # 5MB limit
            raise serializers.ValidationError("File size exceeds 5MB limit")
        
        try:
            # Read and parse CSV
            content = value.read().decode('utf-8')
            csv_reader = csv.DictReader(io.StringIO(content))
            
            if not csv_reader.fieldnames or 'email' not in csv_reader.fieldnames:
                raise serializers.ValidationError("CSV must have an 'email' column")
            
            # Validate email format
            emails = []
            for row_num, row in enumerate(csv_reader, start=2):
                email = row.get('email', '').strip()
                if not email:
                    raise serializers.ValidationError(f"Row {row_num}: Email field is empty")
                
                # Simple email validation
                if '@' not in email or '.' not in email.split('@')[1]:
                    raise serializers.ValidationError(f"Row {row_num}: Invalid email format '{email}'")
                
                emails.append(email)
            
            if not emails:
                raise serializers.ValidationError("CSV contains no valid email addresses")
            
            # Store emails in context for use in create method
            self._emails = emails
            
        except csv.Error as e:
            raise serializers.ValidationError(f"CSV parsing error: {str(e)}")
        except Exception as e:
            raise serializers.ValidationError(f"Error reading CSV file: {str(e)}")
        
        return value
    
    def validate_subject(self, value):
        """Validate subject is not empty"""
        if not value.strip():
            raise serializers.ValidationError("Subject cannot be empty")
        return value
    
    def validate_message(self, value):
        """Validate message is not empty"""
        if not value.strip():
            raise serializers.ValidationError("Message cannot be empty")
        return value
