from django.urls import path
from .views import (
    AvailableServersView, 
    GenerateSessionView, 
    UpdateServerAvailabilityView, 
    Generatetoken,
    VerifySessionView,
    UpdateSessionView,
    LogoutSessionView
)

urlpatterns = [
    path('availableServers/', AvailableServersView.as_view(), name='availableServers'),
    path('session/', GenerateSessionView.as_view(), name='session'),
    path('updateSession/', UpdateSessionView.as_view(), name='updateSession'),
    path('logoutSession/', LogoutSessionView.as_view(), name='logoutSession'),
    path('updateServer/<str:server_name>/', UpdateServerAvailabilityView.as_view(), name='updateServer'),
    path('send/', Generatetoken.as_view(), name='send'),
    path('verifySession/<str:server_name>/', VerifySessionView.as_view(), name='verifySession'),
]