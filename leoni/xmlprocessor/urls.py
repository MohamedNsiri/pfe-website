from django.urls import path
from .views import request_reset_email, delete_validator_report, get_self_reports, confirm_user, add_user, delete_user, view_users, update_role, upload_report, view_all_reports, reset_cred, validate
from rest_framework_simplejwt.views import (TokenObtainPairView, TokenRefreshView, TokenBlacklistView)
from .views import CustomTokenObtainPairView
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('validate/', validate, name='validate'),
    #path('train-model/', train_model, name='train-model'),

    path('token/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),

    path('reset-cred/', reset_cred, name='reset-cred'),
    path('request-reset-email/', request_reset_email),

    path('view-users/', view_users, name='view-users'),
    path('delete-user/<int:user_id>/', delete_user, name='delete-user'),
    path('update-role/<int:user_id>/', update_role, name='update-role'),

    path('reports/self/', get_self_reports, name='get-self-reports'),
    path('delete-report/<int:pk>/', delete_validator_report, name='delete-report'),


    path('add-user/', add_user, name='add-user'),
    path('confirm-user/<str:token>/', confirm_user, name='confirm-user'),
    
    path('upload-report/', upload_report, name='upload-report'),
    path('view-all-reports/', view_all_reports, name='view-all-reports'),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
