from rest_framework import serializers
from .models import VerificationJob, EmailResult

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