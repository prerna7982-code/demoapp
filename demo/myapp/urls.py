from rest_framework import routers
from .views import *
from django.urls import path,include
from django.conf.urls import url
from rest_framework_simplejwt.views import TokenRefreshView
# from rest_framework_social_oauth2.views import *


urlpatterns =[
	path('api/change_password/<int:pk>/', ChangePasswordView.as_view(), name='auth_change_password'),
	path('api/users/',UserDetailView.as_view()),
	path('api/validate_phone/', ValidatePhoneSendOTP.as_view()),
	path('api/validate_otp/', ValidateOTPView.as_view()),
	path('api/token/', MyObtainTokenPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/login/', LoginApiView.as_view(), name='login'),
    path('api/register/',RegisterView.as_view()),
    path('api/logout/',UserLogout.as_view()),
    path('api/update_profile/<int:pk>/', UpdateProfileView.as_view(), name='auth_update_profile'),
    path('api/social/login/', SocialLoginView.as_view())
	]

