from django.urls import path, include

app_name = 'v1'

urlpatterns = [
    path('', include('home.api.v1.urls', namespace='home')),
    path('users/', include('users.api.v1.urls', namespace='users')),
  
]
