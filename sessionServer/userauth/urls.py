from django.urls import path
from .views import LoginAPIView, LogoutAPIView, CustomRefreshTokenView,QRCodeView,SendQRLinkView

urlpatterns = [
    path('login/', LoginAPIView.as_view(), name='login'),
    path('logout/', LogoutAPIView.as_view(), name='logout'),
    path('refresh/', CustomRefreshTokenView.as_view(), name='refresh'),
    path('qrcode/<str:token>/', QRCodeView.as_view(), name='qrcode'),
    path('qrlink/<str:user_id>/', SendQRLinkView.as_view(), name='qrlink'),
]