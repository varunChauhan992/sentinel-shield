from django.urls import path
from .views import public_data_view, mock_login_view, soc_dashboard, toggle_block_ip

urlpatterns = [
   
    path('', public_data_view, name='public-data'),
    path('mock-login/', mock_login_view, name='mock-login'),
    
   
    path('dashboard/', soc_dashboard, name='soc_dashboard'),
    path('dashboard/toggle-ip/<str:ip_address>/', toggle_block_ip, name='toggle_block_ip'),
]