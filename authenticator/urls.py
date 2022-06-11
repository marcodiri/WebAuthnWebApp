from django.urls import path

from . import views


app_name = 'authenticator'
urlpatterns = [
    path('auth/register-request', views.RegisterRequestView.as_view(), name='register_request'),
    path('auth/register-response', views.RegisterResponseView.as_view(), name='register_response'),
]
