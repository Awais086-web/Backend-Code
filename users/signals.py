from django.db.models.signals import post_save
from django.contrib.auth.models import User
from django.dispatch import receiver

from .models import Profile


@receiver(post_save, sender=User)
def create_profile(sender, instance, created, **kwargs):
    if created:
        Profile.objects.create(user=instance)


@receiver(post_save, sender=User)
def save_profile(sender, instance, **kwargs):
    instance.profile.save()



from django.contrib.auth.signals import user_logged_in
from django.dispatch import receiver
from .models import UserProfile

@receiver(user_logged_in)
def create_or_update_user_profile(sender, request, user, **kwargs):
    # Check if a user profile already exists
    try:
        profile = user.userprofile
    except UserProfile.DoesNotExist:
        # If user profile doesn't exist, create a new one
        profile = UserProfile(user=user)

    # Update the user profile fields as per your requirements
    # For example:
    # profile.bio = "Some bio information"
    # profile.avatar = "path/to/avatar.jpg"

    profile.save()