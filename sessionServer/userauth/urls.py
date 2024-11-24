from django.urls import path
from .views import LoginAPIView, LogoutAPIView, CustomRefreshTokenView

urlpatterns = [
    path('login/', LoginAPIView.as_view(), name='login'),
    path('logout/', LogoutAPIView.as_view(), name='logout'),
    path('refresh/', CustomRefreshTokenView.as_view(), name='refresh'),
]