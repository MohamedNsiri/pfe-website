from rest_framework import serializers
from .models import Report

class DatasetGeneration(serializers.Serializer):
    xml_file = serializers.FileField()

class DataPreparationSerializer(serializers.Serializer):
    excel_file = serializers.FileField()

class TrainModelSerializer(serializers.Serializer):
    excel_csv = serializers.FileField()
    xml_csv = serializers.FileField()

from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)

        token['role'] = user.role  # assuming you have a `role` field on your user model

        return token
        
class ReportSerializer(serializers.ModelSerializer):
    username = serializers.CharField(source='user.username', read_only=True)
    sbom_url = serializers.SerializerMethodField()
    dpf_url = serializers.SerializerMethodField()
    content_url = serializers.SerializerMethodField()

    class Meta:
        model = Report
        fields = ['id', 'username', 'sbom_url', 'dpf_url', 'content_url', 'created_at']

    def get_sbom_url(self, obj):
        request = self.context.get('request')
        if obj.sbom and hasattr(obj.sbom, 'url'):
            return request.build_absolute_uri(obj.sbom.url)
        return None

    def get_dpf_url(self, obj):
        request = self.context.get('request')
        if obj.dpf and hasattr(obj.dpf, 'url'):
            return request.build_absolute_uri(obj.dpf.url)
        return None

    def get_content_url(self, obj):
        request = self.context.get('request')
        if obj.content and hasattr(obj.content, 'url'):
            return request.build_absolute_uri(obj.content.url)
        return None