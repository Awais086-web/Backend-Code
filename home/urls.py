from django.urls import path
from .views import About_us,Media_Center,the_exchange,Add_Form,Career,Daily_Downloads,landing_page,legal_framwork,Market_Summary
from . import views
urlpatterns = [
   
    path('Media_Center/',Media_Center,name='Media_Center'),  
    path('the_exchange/',the_exchange,name='the_exchange'),
    path('About_us/',About_us,name='About_us'),
    path('Add_Form/',Add_Form,name='Add_Form'),
    path('Career/',Career,name='Career'),
    path('Daily_Downloads/',Daily_Downloads,name='Daily_Downloads'),
    path('landing_page/',landing_page,name='landing_page'),
    path('legal_framwork/',legal_framwork,name='legal_framwork'),
    path('Market_Summary/',Market_Summary,name='Market_Summary')
]