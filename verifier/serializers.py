from rest_framework import serializers
from .models import VerificationJob, EmailResult

class VerificationJobSerializer(serializers.ModelSerializer):
    class Meta:
        model = VerificationJob
        fields = '__all__'
        # Added processed/valid/invalid counts to read_only so frontend can't fake them
        read_only_fields = ['job_id', 'status', 'progress_percentage', 'created_at', 'completed_at', 'total_count', 'processed_count', 'valid_count', 'invalid_count', 'user']

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