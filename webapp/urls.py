from django.urls import path

from . import views


app_name = 'webapp'
urlpatterns = [
    path('', views.LoginView.as_view(), name='login'),
    path('register/', views.RegisterView.as_view(), name='register'),
    path('register_biometrics/', views.RegisterBiometricsView.as_view(), name='register_biometrics'),
]
