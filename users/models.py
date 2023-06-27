from django.db import models
from django.contrib.auth.models import User
from PIL import Image


from django.conf import settings
from django.utils import timezone


# Extending User Model Using a One-To-One Link
class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    avatar = models.ImageField(default='default.jpg', upload_to='profile_images')
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    otp = models.CharField(max_length=6,null=True, blank=True)
    otp_expiry_time = models.DateTimeField(default=timezone.now,null=True, blank=True) 
    bio = models.TextField()
    address = models.CharField(max_length=100, null=True, blank=True)
    phone_number = models.CharField(max_length=20, null=True, blank=True)
    

    def __str__(self):
        return self.user.username

    # resizing images
    def save(self, *args, **kwargs):
        super().save()

        img = Image.open(self.avatar.path)

        if img.height > 100 or img.width > 100:
            new_img = (100, 100)
            img.thumbnail(new_img)
            img.save(self.avatar.path)
            
            


from django.db import models
from ckeditor.fields import RichTextField

class TermsAndConditions(models.Model):
    content = RichTextField()

    def __str__(self):
        return "Terms and Conditions"

class PrivacyPolicy(models.Model):
    content = RichTextField()

    def __str__(self):
        return "Privacy Policy"

from django.db import models
from django.contrib.auth.models import User

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    # Add additional fields for the user profile as per your requirements
    # For example:
    # bio = models.TextField(blank=True)
    # avatar = models.ImageField(upload_to='avatars/', blank=True)

    def __str__(self):
        return self.user.username