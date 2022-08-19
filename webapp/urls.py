from django.urls import path

from . import views


app_name = 'webapp'
urlpatterns = [
    path('', views.IndexView.as_view(), name='index'),
    path('login/', views.LoginView.as_view(), name='login'),
    path('register/', views.RegisterView.as_view(), name='register'),
    path('register_biometrics/', views.RegisterBiometricsView.as_view(), name='register_biometrics'),
    path('login_biometrics/', views.LoginBiometricsView.as_view(), name='login_biometrics'),
]
