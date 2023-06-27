from django.urls import path
from . import views, viewsets
from .views import UserSignupAPIView, UserLoginAPIView,ResetPasswordAPIView,DeleteAccountAPIView


app_name = 'users'

urlpatterns = [
    path('api/signup/', UserSignupAPIView.as_view(), name='user-signup'),
    path('api/login/', UserLoginAPIView.as_view(), name='user-login'),
    path('api/reset-password/', ResetPasswordAPIView.as_view(), name='reset-password'),
    path('api/delete-account/', DeleteAccountAPIView.as_view(), name='delete-account'),
]
