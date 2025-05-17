from django.db import models
from django.contrib.auth.models import User
from django.contrib.auth.hashers import make_password, check_password

class User(models.Model):
    username = models.CharField(max_length=100)
    email = models.EmailField()
    password = models.CharField(max_length=128)  # Increased length for hashed passwords
    mobile = models.CharField(max_length=15,default='0000000000')
    is_verified = models.BooleanField(default=False)
    role = models.CharField(max_length=50)

    def __str__(self):
        return self.username

    def set_password(self, raw_password):
        self.password = make_password(raw_password)
        self.save()

    def check_password(self, raw_password):
        return check_password(raw_password, self.password)

class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    name = models.CharField(max_length=100)
    bio = models.TextField(blank=True)
    image = models.ImageField(upload_to='profile_images/', blank=True, null=True)

    def __str__(self):
        return self.user.username

class OTPRecord(models.Model):
    email = models.EmailField()
    otp = models.CharField(max_length=6)
    
    def __str__(self):
        return f"OTP for {self.email} ({self.otp})"

class Resume(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    file = models.FileField(upload_to='resumes/')
    name = models.CharField(max_length=255)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=20, default='pending')  # pending, parsed, error
    parsed_data = models.JSONField(null=True, blank=True)

    def __str__(self):
        return f"{self.name} - {self.user.username}"

    class Meta:
        db_table = 'resumes'
        ordering = ['-uploaded_at']

class SelectedResume(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    name = models.CharField(max_length=255)
    resume = models.ForeignKey(Resume, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.name} - {self.user.username}"

class FormData(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    name = models.CharField(max_length=255)
    email = models.EmailField()
    phone = models.CharField(max_length=20)
    skills = models.JSONField(default=list)
    experience = models.TextField()
    education = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = 'Form Data'
        verbose_name_plural = 'Form Data'

    def __str__(self):
        return f"{self.name} - {self.user.email}"