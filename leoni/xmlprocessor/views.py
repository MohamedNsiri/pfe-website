from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework import status
from lxml import etree
import pandas as pd
from .serializers import DatasetGeneration, DataPreparationSerializer, ReportSerializer
from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.hashers import check_password, make_password
from django.core.exceptions import ValidationError
from rest_framework_simplejwt.tokens import RefreshToken
from .utils import SBOMValidator
from .models import User, Report
from .permissions import IsAdmin, IsOverseer, IsValidator
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.core.mail import EmailMessage
from django.utils.timezone import now
from rest_framework_simplejwt.token_blacklist.models import OutstandingToken
from django.core.exceptions import ObjectDoesNotExist
from rest_framework_simplejwt.authentication import JWTAuthentication
from django.http import FileResponse
import os
import tempfile
from django.conf import settings
from django.core.files import File
import uuid 
from django.utils.html import strip_tags
import secrets
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.core.files.base import ContentFile
from django.core.cache import cache

@api_view(["POST"])
def validate(request):
    try:
        
        validator = SBOMValidator(
            xml_file_path=request.FILES['sbom'],
            excel_file_path=request.FILES['excel_file']
        )
        validator.wcpr = request.data.get("workcenter_plantreference")
        validator.wcpar = request.data.get("workcenter_productionareareference")
        validator.wcusfa = request.data.get("wokrcenter_usesinglefileassembly")

        sheetwirelength = validator.get_sheet_by_name("Wires Lengths")
        sbomsub = validator.get_subassemblies(flatten_attributes=True)
        results = validator.validate()
        gen_results = validator.generate_report(results)

        with open(gen_results['report_path'], 'rb') as pdf_file:
            pdf_content = pdf_file.read()

        try:
            report = Report.objects.create(
                user=request.user,
                sbom=request.FILES['sbom'],
                dpf=request.FILES['excel_file']
            )
        except Exception as e:
            print(f"Failed to create Report: {str(e)}")
            raise

        report.content.save(
            os.path.basename(gen_results['report_path']),
            ContentFile(pdf_content)
        )

        os.remove(gen_results['report_path'])
        response = FileResponse(report.content.open('rb'), content_type='application/pdf')
        response['Content-Disposition'] = f'attachment; filename="{os.path.basename(report.content.name)}"'
        #return Response({"wires in excel": f"sheets wire: {sheetwirelength["data"]}", "wires in xml": f"xml wire: {sbomsub[6].get('quantity')}"})
        return response

    except Exception as e:
        print(f"Error in validate(): {str(e)}")
        return Response({"error": str(e)}, status=400)


@api_view(["POST"])
def generate_dataset(request):
    serializer = DatasetGeneration(data=request.data)

    if serializer.is_valid():
        xml_file = request.FILES.get("xml_file")

        if not xml_file:
            return Response({"error": "XML File Needed"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            xml_file = parse_xml(xml_file)
            
            return Response({
                "message": "Dataset Generated.",
            })

        except Exception as e:
            return Response({"error": f"File processing error: {e}"}, status=status.HTTP_400_BAD_REQUEST)

    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(["POST"])
def data_preparation_file_process(request):
    serializer = DataPreparationSerializer(data=request.data)

    if serializer.is_valid():
        excel_file = request.FILES.get("excel_file")

        if not excel_file:
            return Response({"error": "Excel File Needed"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            excel_file = parse_excel(excel_file)
            
            return Response({
                "message": "Excel Dataset Generated.",
            })

        except Exception as e:
            return Response({"error": f"File processing error: {e}"}, status=status.HTTP_400_BAD_REQUEST)

    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

#Validator
@api_view(["GET"])
def get_self_reports(request):
    reports = Report.objects.filter(user=request.user).order_by('-created_at')
    serializer = ReportSerializer(reports, many=True, context={'request': request})
    return Response(serializer.data)

@api_view(['DELETE'])
def delete_validator_report(request, pk):
    try:
        report = Report.objects.get(id=pk, user=request.user)
    except Report.DoesNotExist:
        return Response(
            {"error": "Report not found or you don't have permission"},
            status=status.HTTP_404_NOT_FOUND
        )
    
    report.sbom.delete(save=False)
    report.dpf.delete(save=False)
    report.content.delete(save=False)
    
    report.delete()
    
    return Response(
        {"message": "Report deleted successfully"},
        status=status.HTTP_204_NO_CONTENT
    )
from django.views.decorators.http import require_http_methods

@require_http_methods(["POST", "OPTIONS"])
@api_view(["POST"])
def login(request):
    username = request.data.get("username")
    password = request.data.get("password")

    if not username or not password:
        return Response({"error": "Username and password are required"}, status=400)

    user = authenticate(username=username, password=password)

    if user is not None:
        refresh = RefreshToken.for_user(user)
        user.last_login = now()
        user.save(update_fields=["last_login"])
        return Response({
            "refresh": str(refresh),
            "access": str(refresh.access_token),
            "role": user.role,
        })
    else:
        return Response({"error": "Invalid username or password"}, status=401)

@api_view(["POST"])
def reset_cred(request):
    user = request.user
    old_password = request.data.get("old_password")
    new_password = request.data.get("new_password")

    if not all([old_password, new_password]):
        return Response(
            {"error": "Old password and new password are required."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    if not user.check_password(old_password):
        return Response(
            {"error": "Old password is incorrect."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    user.password = make_password(new_password)
    user.save()

    return Response(
        {"message": "Password reset successfully."},
        status=status.HTTP_200_OK,
    )

@api_view(["POST"])
def add_user(request):
    try:
        data = request.data

        if not all(key in data for key in ["email", "username", "password", "role"]):
            return Response({"error": "Missing required fields"}, status=400)

        valid_roles = [choice[0] for choice in User.ROLE_CHOICES]
        if data["role"] not in valid_roles:
            return Response({"error": "Invalid role"}, status=400)

        if User.objects.filter(email=data["email"]).exists():
            return Response({"error": "Email already exists"}, status=400)

        raw_password = data["password"]  # Save the plain password

        user = User.objects.create_user(
            username=data["username"],
            email=data["email"],
            password=raw_password,
            first_name=data.get("first_name", ""),
            last_name=data.get("last_name", ""),
            is_active=False
        )

        user.role = data["role"]
        user.is_superuser = data["role"] == "admin"
        user.is_staff = data["role"] != "admin"

        confirmation_token = secrets.token_urlsafe(32)
        user.confirmation_token = confirmation_token
        user.save()

        confirmation_url = request.build_absolute_uri(
            reverse('confirm-user', kwargs={'token': confirmation_token})
        )

        subject = "Confirm Your Account Creation"
        html_message = render_to_string('email/confirmation_email.html', {
            'user': user,
            'confirmation_url': confirmation_url,
            'plain_password': raw_password  # Pass to template if needed
        })
        plain_message = strip_tags(html_message)

        send_mail(
            subject,
            plain_message,
            settings.DEFAULT_FROM_EMAIL,
            [user.email],
            html_message=html_message,
            fail_silently=False
        )
        print("plain password ", raw_password)
        cache.set(f"user_plain_pw_{user.id}", raw_password, timeout=600)

        return Response(
            {
                "message": "Confirmation email sent",
                "status": "pending_confirmation",
            },
            status=201,
        )

    except ValidationError as e:
        return Response({"error": str(e)}, status=400)
    except Exception as e:
        return Response({"error": "An error occurred: " + str(e)}, status=500)


@api_view(["GET"])
def confirm_user(request, token):
    try:
        user = User.objects.get(confirmation_token=token)
        user.is_active = True
        user.confirmation_token = None
        user.save()
        plain_password = cache.get(f"user_plain_pw_{user.id}")
        
        # Send welcome email with credentials
        subject = "Your Account Has Been Created"
        html_message = render_to_string('email/welcome_email.html', {
            'user': user,
            'username': user.username,
            'password': plain_password,
        })
        plain_message = strip_tags(html_message)
        
        send_mail(
            subject,
            plain_message,
            settings.DEFAULT_FROM_EMAIL,
            [user.email],
            html_message=html_message,
            fail_silently=False
        )
        
        return Response({"message": "User confirmed successfully"}, status=200)
        
    except User.DoesNotExist:
        return Response({"error": "Invalid confirmation token"}, status=400)
    except Exception as e:
        return Response({"error": str(e)}, status=500)

from rest_framework_simplejwt.views import TokenObtainPairView
from .serializers import CustomTokenObtainPairSerializer
class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer

@api_view(["DELETE"])
#@permission_classes([IsAdmin]) 
def delete_user(request, user_id):
    try:
        user = User.objects.get(id=user_id)
        user.delete()
        return Response({"message": "User deleted successfully"}, status=200)
    except User.DoesNotExist:
        return Response({"error": "User not found"}, status=404)

@api_view(["PUT"])
#@permission_classes([IsAdmin])
def update_role(request, user_id):
    try:
        user = User.objects.get(id=user_id)
        new_role = request.data.get("role")

        if new_role not in ["admin", "validator", "overseer"]:
            return Response({"error": "Invalid role provided."}, status=status.HTTP_400_BAD_REQUEST)

        user.role = new_role  # Make sure your User model has a 'role' field
        user.save()
        return Response({"message": "User role updated successfully"}, status=status.HTTP_200_OK)
    except User.DoesNotExist:
        return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)



#Overseer
@api_view(["POST"])
@permission_classes([IsOverseer]) 
def leave_comment(request):
    pass

@api_view(["GET"])
@permission_classes([IsAdmin | IsOverseer])
def view_users(request):
    users = User.objects.all().values("id", "username", "email", "role", "is_superuser", "is_staff")
    return Response(list(users), status=200)

@api_view(["POST"])
def send_email(request):
    message = request.data.get("message")
    recipient_email = request.data.get("email")
    subject = request.data.get("subject")

    if not all([message, recipient_email, subject]):
        return Response({"error": "Missing required fields"}, status=status.HTTP_400_BAD_REQUEST)

    try:
        send_mail(
            subject=subject,
            message=message,
            from_email=None,
            recipient_list=[recipient_email],
            fail_silently=False,
        )
        return Response({"message": "Email sent successfully"}, status=status.HTTP_200_OK)

    except Exception as e:
        return Response({"error": f"Failed to send email: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(["GET"])
#@permission_classes([IsOverseer | IsAdmin]) 
def view_all_reports(request):
    reports = Report.objects.all().order_by('-created_at')
    serializer = ReportSerializer(reports, many=True, context={'request': request})
    return Response(serializer.data)

@api_view(["POST"])
def upload_report(request):
    user = request.user
    content = request.FILES.get("content")
    sbom = request.FILES.get("sbom")
    dpf = request.FILES.get("dpf")

    if not all([content, sbom, dpf]):
        return Response(
            {"error": "All files (content, sbom, dpf) are required."},
            status=status.HTTP_400_BAD_REQUEST
        )

    report = Report.objects.create(
        user=user,
        content=content,
        sbom=sbom,
        dpf=dpf
    )

    return Response({
        "message": "Report uploaded successfully.",
        "report_id": report.id,
        "created_at": report.created_at,
        "user": report.user.username
    }, status=status.HTTP_201_CREATED)

@api_view(['POST'])
def request_reset_email(request):
    email = request.data.get('email')
    if not email:
        return Response({'error': 'Email is required.'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        user = User.objects.get(email=email)
        new_password = get_random_string(length=8)
        
        user.password = make_password(new_password)
        user.save()

        send_mail(
            subject='Your New Password',
            message=f'Your new password is: {new_password}\n\nPlease login and change it immediately.',
            from_email='noreply@example.com',
            recipient_list=[email],
            fail_silently=False,
        )

        return Response(
            {'message': 'A new password has been sent to your email. Please check your inbox.'}, 
            status=status.HTTP_200_OK
        )

    except User.DoesNotExist:
        return Response(
            {'error': 'No user found with this email.'}, 
            status=status.HTTP_404_NOT_FOUND
        )