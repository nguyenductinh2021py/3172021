from django.urls import path
from authentication.views import RegisterView, LoginView, LogoutView, CheckToken, ChangePasswordView

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('check_token/', CheckToken.as_view(), name='check_token'),
    path('change_password/', ChangePasswordView.as_view(), name='change_password')
]
