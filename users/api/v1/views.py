from rest_framework.response import Response
from rest_framework.views import APIView
from users.models import User
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login
from django.utils.crypto import get_random_string
from django.contrib.auth.tokens import default_token_generator
from django.contrib.sites.shortcuts import get_current_site
from django.contrib.auth.models import User
from django.core.mail import send_mail
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.tokens import RefreshToken
from datetime import timedelta
from django.contrib.auth.tokens import default_token_generator
from poritiy_gold.settings import AUTHENTICATION_BACKENDS
from django.views.decorators.csrf import csrf_exempt

class UserSignupAPIView(APIView):
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')
        email = request.data.get('email')

        if not username or not password or not email:
            return Response({'detail': 'Username, password, and email are required.'}, status=status.HTTP_400_BAD_REQUEST)

        if User.objects.filter(username=username).exists():
            return Response({'detail': 'Username already exists. Please choose a different username.'}, status=status.HTTP_409_CONFLICT)

        otp = get_random_string(length=6, allowed_chars='0123456789')
        message = f'Your OTP for signup: {otp}'
        send_mail('Signup OTP', message, 'noreply@example.com', [email])

        user = User.objects.create_user(username=username, password=password, email=email)
        user.otp = otp
        user.save()

        return Response({'detail': 'OTP sent for verification.'}, status=status.HTTP_200_OK)


class OTPVerificationAPIView(APIView):
    def post(self, request):
        username = request.data.get('username')
        otp = request.data.get('otp')

        if not username or not otp:
            return Response({'detail': 'Username and OTP are required.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(username=username, otp=otp)
        except User.DoesNotExist:
            return Response({'detail': 'Invalid username or OTP.'}, status=status.HTTP_400_BAD_REQUEST)

        user.is_active = True
        user.otp = ''
        user.save()

        user = authenticate(request, username=username, password=user.password)
        login(request, user)

        return Response({'detail': 'OTP verification successful. User logged in.'}, status=status.HTTP_200_OK)


class UserLoginAPIView(APIView):
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')

        if not username or not password:
            return Response({'detail': 'Username and password are required.'}, status=status.HTTP_400_BAD_REQUEST)

        User = get_user_model()

        users = User.objects.filter(username=username)

        if not users:
            return Response({'detail': 'Invalid username or password.'}, status=status.HTTP_401_UNAUTHORIZED)

        for user in users:
            if user.check_password(password):
                refresh = RefreshToken.for_user(user)
                access_token = str(refresh.access_token)
                refresh_token = str(refresh)

                # Set the token expiration to 30 minutes
                refresh.access_token.set_exp(lifetime=timedelta(minutes=30))

                # Set the refresh token expiration to 30 minutes as well
                refresh.set_exp(lifetime=timedelta(minutes=30))

                return Response({
                    'access_token': access_token,
                    'refresh_token': refresh_token,
                    'expires_in': 1800,  # Expiration time in seconds
                }, status=status.HTTP_200_OK)

        return Response({'detail': 'Invalid username or password.'}, status=status.HTTP_401_UNAUTHORIZED)


class ResetPasswordAPIView(APIView):
    def initial(self, request, *args, **kwargs):
        super().initial(request, *args, **kwargs)
        setattr(request, '_dont_enforce_csrf_checks', True)

    def get(self, request, *args, **kwargs):
        # Handle GET request for CSRF token retrieval
        # ...

        return Response({'detail': 'CSRF token retrieved.'}, status=200)

    def post(self, request, *args, **kwargs):
        # Handle POST request for reset password logic
        # ...

        return Response({'detail': 'Reset password request processed.'}, status=200)


class DeleteAccountAPIView(APIView):
    @csrf_exempt
    def post(self, request, *args, **kwargs):
        email = request.data.get('email', None)
        if not email:
            return Response({
                'detail': 'Email is required.'
            }, status=status.HTTP_400_BAD_REQUEST)

        User = get_user_model()

        users = User.objects.filter(email=email)

        if not users:
            return Response({
                'detail': 'No user found with this email.'
            }, status=status.HTTP_404_NOT_FOUND)

        users.delete()

        return Response({
            'detail': 'Account deleted successfully.'
        }, status=status.HTTP_200_OK)