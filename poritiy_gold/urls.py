from django.contrib import admin
from django.conf import settings
from django.conf.urls.static import static
from django.contrib.auth import views as auth_views
from users.views import CustomLoginView, ResetPasswordView, ChangePasswordView
from django.urls import include, path, re_path
from users.forms import LoginForm
from users.views import terms_and_conditions_view
from users.api.v1.views import UserSignupAPIView, UserLoginAPIView,ResetPasswordAPIView,DeleteAccountAPIView


urlpatterns = [
    
    #for admin 
    path('admin/', admin.site.urls),  
    path('ckeditor/', include('ckeditor_uploader.urls')),
     #admin urls end
     
     #for api app modul
     path('v1/', include('users.api.v1.urls', namespace='v1')),
     path('api/signup/', UserSignupAPIView.as_view(), name='user-signup'),
     path('api/login/', UserLoginAPIView.as_view(), name='user-login'),
     path('api/reset-password/', ResetPasswordAPIView.as_view(), name='reset-password'),
     path('api/delete-account/', DeleteAccountAPIView.as_view(), name='delete-account'),
     # end 
     
     #for home static pages
     path('home/', include('home.urls')),
     #end 
     
     # for user authication

    path('', include('users.urls')),
    
    path('login/', CustomLoginView.as_view(redirect_authenticated_user=True, template_name='users/login.html',
                                           authentication_form=LoginForm), name='login'),
    

    path('logout/', auth_views.LogoutView.as_view(template_name='users/logout.html'), name='logout'),
    path('password-reset/', ResetPasswordView.as_view(), name='password_reset'),
    path('password-reset-confirm/<uidb64>/<token>/',
         auth_views.PasswordResetConfirmView.as_view(template_name='users/password_reset_confirm.html'),
         name='password_reset_confirm'),

    path('password-reset-complete/',
         auth_views.PasswordResetCompleteView.as_view(template_name='users/password_reset_complete.html'),
         name='password_reset_complete'),
    

    path('password-change/', ChangePasswordView.as_view(), name='password_change'),
    path('auth/', include('social_django.urls', namespace='social')),
    

] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
