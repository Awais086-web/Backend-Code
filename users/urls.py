from django.urls import path,include
from .views import  profile, RegisterView,terms_and_conditions_view,privacy_policy_view,otp_verification,home
from . import views

urlpatterns = [
    
    path('', home, name='users-home'),
    path('register/', RegisterView.as_view(), name='users-register'),
    path('profile/', profile, name='users-profile'),
    path('terms_and_conditions/', terms_and_conditions_view, name='users-terms_and_conditions'),
    path('privacy_policy/',privacy_policy_view,name='users-privacy_policy' ),
    path('otp_verification/<str:uidb64>/<str:token>/', otp_verification, name='users-otp_verification'),
    

  
]

