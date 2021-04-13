from rest_framework import routers

from .views import *
from django.urls import path,include
from django.conf.urls import url
from rest_framework_simplejwt import views as jwt_views
from rest_framework_simplejwt.views import TokenRefreshView

# router = routers.DefaultRouter(trailing_slash=True)
# router.register('api', AuthViewSet, basename='api')


# from auth.views import MyObtainTokenPairView
# from rest_framework_simplejwt.views import TokenRefreshView


# urlpatterns = [
#     path('login/', MyObtainTokenPairView.as_view(), name='token_obtain_pair'),
#     path('login/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
#     path('change_password/<int:pk>/', ChangePasswordView.as_view(), name='auth_change_password'),
# ]


urlpatterns =[
	path('api/change_password/<int:pk>/', ChangePasswordView.as_view(), name='auth_change_password'),
	path('api/users/',UserDetailView.as_view()),
	path('api/validate_phone/', ValidatePhoneSendOTP.as_view()),
	path('api/validate_otp/', ValidateOTPView.as_view()),
	path('api/login/', MyObtainTokenPairView.as_view(), name='token_obtain_pair'),
    path('api/login/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/register/',RegisterView.as_view()),
    path('api/logout/',UserLogout.as_view()),
    path('api/logout_all/', LogoutAllView.as_view(), name='auth_logout_all'),
    path('api/update_profile/<int:pk>/', UpdateProfileView.as_view(), name='auth_update_profile'),
    path('oauth/login/', SocialLoginView.as_view())
	]

# urlpatterns += router.urls