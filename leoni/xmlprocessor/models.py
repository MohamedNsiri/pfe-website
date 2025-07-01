from django.contrib.auth.models import AbstractUser
from django.db import models

class User(AbstractUser):
    ROLE_CHOICES = [
        ('admin', 'Admin'),
        ('validator', 'Validator'),
        ('overseer', 'Overseer'),
    ]

    email = models.EmailField(unique=True)
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default='validator')
    confirmation_token = models.CharField(max_length=64, null=True, blank=True)


    def __str__(self):
        return self.username


class Report(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='reports')
    content = models.FileField(upload_to='reports/')
    sbom = models.FileField(upload_to='xml_files/')
    dpf = models.FileField(upload_to='excel_files/')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Report by {self.user.username} on {self.created_at.strftime('%Y-%m-%d %H:%M')}"
