import datetime
import random
import smtplib
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login
from django.utils.crypto import get_random_string
from django.contrib.auth import authenticate, login
from datetime import timedelta
from email.mime.text import MIMEText
from django.contrib.auth.tokens import default_token_generator
from django.contrib.sites.shortcuts import get_current_site
from django.contrib.auth.models import User
from django.http import JsonResponse
from django.views import View
from django.core.exceptions import MultipleObjectsReturned
from django.core.mail import send_mail
from django.shortcuts import render, redirect
from django.urls import reverse, reverse_lazy
from django.contrib.auth.views import LoginView, PasswordResetView, PasswordChangeView
from django.contrib import messages
from django.contrib.messages.views import SuccessMessageMixin
from django.utils import timezone
from django.core.mail import EmailMessage
from django.views import View
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str

from poritiy_gold.settings import AUTHENTICATION_BACKENDS

from .models import TermsAndConditions, PrivacyPolicy
from .forms import RegisterForm, LoginForm, UpdateUserForm, UpdateProfileForm
from rest_framework import serializers
from .models import User



User = get_user_model()


def home(request):
    return render(request, 'users/home.html')

class RegisterView(View):
    form_class = RegisterForm
    initial = {'key': 'value'}
    template_name = 'users/register.html'

    def dispatch(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            return redirect(to='/')

        return super(RegisterView, self).dispatch(request, *args, **kwargs)

    def send_otp_email(self, user, otp):
        subject = 'OTP Verification'
        message = f'Hello, For verification of your account, use this OTP: {otp}'
        email = EmailMessage(subject, message, to=[user.email])
        email.send()

    def get(self, request, *args, **kwargs):
        form = self.form_class(initial=self.initial)
        return render(request, self.template_name, {'form': form})

    def post(self, request, *args, **kwargs):
        form = self.form_class(request.POST)

        if form.is_valid():
            user = form.save()

            otp = random.randint(100000, 999999)

            profile = user.profile
            profile.otp = otp
            profile.otp_expiry_time = timezone.now() + timedelta(minutes=2)  # Set OTP expiration time
            profile.save()

            self.send_otp_email(user, otp)

            username = form.cleaned_data.get('username')
            messages.success(request, f'Account created for {username}. Please check your email for OTP verification.')

            uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
            token = default_token_generator.make_token(user)
            return redirect('users-otp_verification', uidb64=uidb64, token=token)

        return render(request, self.template_name, {'form': form})


def otp_verification(request, uidb64, token):
    User = get_user_model()
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user is not None and default_token_generator.check_token(user, token):
        if request.method == 'POST':
            entered_otp = request.POST.get('otp')

            # Get the associated profile
            profile = user.profile

            # Check if OTP is valid and not expired
            if profile.otp == entered_otp and profile.otp_expiry_time > timezone.now():
                # OTP verification successful
                user.is_active = True
                user.save()

                # Log in the user
                user.backend = 'django.contrib.auth.backends.ModelBackend'  # Set the backend attribute
                login(request, user)

                messages.success(request, 'OTP verified successfully. You have been logged in.')
                return redirect('users-profile')
            else:
                messages.error(request, 'Invalid OTP or OTP has expired. Please try again.')
                return redirect('users-otp_verification', uidb64=uidb64, token=token)
        else:
            return render(request, 'users/otp_verification.html', {'uidb64': uidb64, 'token': token})

    # Return an HTTP response in case of invalid OTP verification link or token
    messages.error(request, 'Invalid OTP verification link or token.')
    return redirect('register')

class CustomLoginView(LoginView):
    form_class = LoginForm

    def form_valid(self, form):
        remember_me = form.cleaned_data.get('remember_me')

        if not remember_me:
            self.request.session.set_expiry(0)
            self.request.session.modified = True

        return super().form_valid(form)

    def get_success_url(self):
        return '/users-profile/'

class ResetPasswordView(SuccessMessageMixin, PasswordResetView):
    template_name = 'users/password_reset.html'
    email_template_name = 'users/password_reset_email.html'
    subject_template_name = 'users/password_reset_subject'
    success_message = "We've emailed you instructions for setting your password, " \
                      "if an account exists with the email you entered. You should receive them shortly." \
                      " If you don't receive an email, " \
                      "please make sure you've entered the address you registered with, and check your spam folder."

    def get_success_url(self):
        return '/password-reset-confirm/<uidb64>/<token>/'

class ChangePasswordView(SuccessMessageMixin, PasswordChangeView):
    template_name = 'users/change_password.html'
    success_message = "Successfully changed your password"
    success_url = reverse_lazy('users-home')

@login_required
def profile(request):
    if request.method == 'POST':
        user_form = UpdateUserForm(request.POST, instance=request.user)
        profile_form = UpdateProfileForm(request.POST, request.FILES, instance=request.user.profile)

        if user_form.is_valid() and profile_form.is_valid():
            user_form.save()
            profile_form.save()
            messages.success(request, 'Your profile is updated successfully')
            return redirect(to='users-profile')
    else:
        user_form = UpdateUserForm(instance=request.user)
        profile_form = UpdateProfileForm(instance=request.user.profile)

    return render(request, 'users/profile.html', {'user_form': user_form, 'profile_form': profile_form})

def terms_and_conditions_view(request):
    terms_and_conditions = TermsAndConditions.objects.first()
    template_name = 'users/terms_and_conditions.html'
    return render(request, template_name, {'terms_and_conditions': terms_and_conditions})

def privacy_policy_view(request):
    privacy_policy = PrivacyPolicy.objects.first()
    template_name = 'users/privacy_policy.html'
    return render(request, template_name, {'privacy_policy': privacy_policy})


