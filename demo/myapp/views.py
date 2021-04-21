from django.core.exceptions import ImproperlyConfigured
from rest_framework import viewsets, status, generics
from rest_framework.views import APIView
# from rest_framework.decorators import action
from rest_framework.permissions import AllowAny,IsAuthenticated,IsAuthenticatedOrReadOnly
from rest_framework.response import Response
from .models import CustomUser
from .utils import *
from django.contrib.auth import get_user_model, logout, login
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from twilio.rest import Client
from .serializers import *
from .exception_handling import *
import random
import redis
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.authentication import BasicAuthentication
from rest_framework_simplejwt.token_blacklist.models import OutstandingToken,BlacklistedToken
from drf_yasg.utils import swagger_auto_schema
from urllib.error import HTTPError

User = get_user_model()

r = redis.Redis(host='127.0.0.1',port=6379, db=0)



class MyObtainTokenPairView(TokenObtainPairView):
	authentication_classes = [BasicAuthentication]
	parser_classes = (FormParser, MultiPartParser)
	permission_classes = (IsAuthenticated,)
	serializer_class = MyTokenObtainPairSerializer

class LoginApiView(generics.GenericAPIView):
	authentication_classes = [JWTAuthentication]
	parser_classes = (FormParser, MultiPartParser)
	permission_classes = (IsAuthenticated,)
	serializer_class = UserLoginSerializer
	def post(self,request):
		serializer = self.serializer_class(data=request.data)
		serializer.is_valid(raise_exception=True)
		# serializer.save()

		return Response(data = {'status':'1',"message":"successfully logged in"})


class RegisterView(generics.CreateAPIView):
	authentication_classes = [BasicAuthentication]
	parser_classes = (FormParser, MultiPartParser)
	queryset = User.objects.all()
	permission_classes = (IsAuthenticated,)
	serializer_class = UserRegisterSerializer


class UserDetailView(generics.ListAPIView):
	authentication_classes = [JWTAuthentication]
	parser_classes = (FormParser, MultiPartParser)
	queryset = User.objects.all()
	permission_classes = (IsAuthenticated,)
	serializer_class = AuthUserSerializer


class UserLogout(generics.GenericAPIView):
	authentication_classes = [JWTAuthentication]
	parser_classes = (FormParser, MultiPartParser)
	permission_classes = (IsAuthenticated,)
	serializer_class = LogoutSerializer

	def post(self,request):
		serializer = self.serializer_class(data=request.data)
		serializer.is_valid(raise_exception=True)
		serializer.save()

		return Response(data = {"status":"1","message":"successfully logged out"})



class ChangePasswordView(generics.UpdateAPIView):
	authentication_classes = [JWTAuthentication]
	parser_classes = (FormParser, MultiPartParser)
	queryset = User.objects.all()
	permission_classes = (IsAuthenticated,)
	serializer_class = ChangePasswordSerializer

import twilio

class ValidatePhoneSendOTP(generics.CreateAPIView):
	# authentication_classes = [JWTAuthentication]
	parser_classes = (FormParser, MultiPartParser)
	serializer_class = PhoneOtpGenerate
	permission_classes = [AllowAny]
	def post(self, request, *args, **kwargs):
		serializer = self.get_serializer(data=request.data)

		if serializer.is_valid(raise_exception=True):
			country_code = serializer.validated_data['country_code']
			phone_number = serializer.validated_data['phone_number']
			if country_code and phone_number:
				country_code = str(country_code)
				phone = str(phone_number)
				try:
					otp = send_otp(country_code,phone)
					try:
						user_otp = r.set(phone,otp,120)
					except HTTPError as error:
						return Response({
							"error": {
								"details": str(error)
							}})
					otp_new = str(otp)
					count = 0
					return Response({'status':1,'response_data':{
					'message': "otp created", 
					'otp' : otp_new
						}})
				except HTTPError as error:
					return Response({
						"error": {
							"details": str(error)
						}})



class ValidateOTPView(generics.CreateAPIView):
	authentication_classes = [JWTAuthentication]
	permission_classes = [IsAuthenticated]
	parser_classes = (FormParser, MultiPartParser)
	serializer_class = ValidateOTP
	def post(self, request):
		serializer = self.get_serializer(data=request.data)

		if serializer.is_valid(raise_exception=True):
			country_code = serializer.validated_data['country_code']
			phone = serializer.validated_data['phone']
			otp_sent   = serializer.validated_data['otp']

			if country_code and phone and otp_sent:
				old = CustomUser.objects.filter(phone__iexact = phone, country_code__iexact = country_code)
				if old.exists():
					return Response({'status':1,'response_data':{'message':'user already exists'}})
				else:
					otp = r.get(phone)
					if otp != None:
						otp = otp.decode("utf-8")
						if str(otp) == str(otp_sent):
							return Response({'status':1,'response_data':{
											'otp': otp,'message':'successfully verified otp'}})
						else:
							return Response({'status':1,'response_data':{
										'message':'invalid otp please try again'}})
					else:
						return Response({'status':1,'response_data':{
										'message':'otp expired try again'}})
			else:
				return Response({'status':1,'response_data':{'error':{
								'error_code' : 6, 
								'error_mess' : error_codes[6]
								}}
							})
		else:
			return Response({'status':1,'response_data':{'error':{
							'error_code' : 9, 
							'error_mess' : error_codes[9]
							}}
						})


class UpdateProfileView(generics.UpdateAPIView):
	authentication_classes = [JWTAuthentication]
	parser_classes = (FormParser, MultiPartParser)
	queryset = User.objects.all()
	permission_classes = (IsAuthenticated,)
	serializer_class = UpdateUserSerializer

from social_django.utils import load_strategy, load_backend
from social_core.backends.oauth import BaseOAuth2
from social_core.exceptions import MissingBackend, AuthTokenError, AuthForbidden

 
class SocialLoginView(generics.GenericAPIView):
	"""Log in using facebook"""
	parser_classes = (FormParser, MultiPartParser)
	serializer_class = SocialSerializer
	authentication_classes = [BasicAuthentication]
	permission_classes = [IsAuthenticated]
 
	def post(self, request):
		"""Authenticate user through the provider and access_token"""
		serializer = self.serializer_class(data=request.data)
		serializer.is_valid(raise_exception=True)
		provider = serializer.data.get('provider', None)
		strategy = load_strategy(request)
 
		try:
			backend = load_backend(strategy=strategy, name=provider,
			redirect_uri=None)
 
		except MissingBackend:
			return Response({'error': 'Please provide a valid provider'},
			status=status.HTTP_400_BAD_REQUEST)
		try:
			if isinstance(backend, BaseOAuth2):
				access_token = serializer.data.get('access_token')
			user = backend.do_auth(access_token)
		except HTTPError as error:
			return Response({
				"error": {
					"access_token": "Invalid token",
					"details": str(error)
				}
			}, status=status.HTTP_400_BAD_REQUEST)
		except AuthTokenError as error:
			return Response({
				"error": "Invalid credentials",
				"details": str(error)
			}, status=status.HTTP_400_BAD_REQUEST)
 
		try:
			authenticated_user = backend.do_auth(access_token, user=user)
		
		except HTTPError as error:
			return Response({
				"error":"invalid token",
				"details": str(error)
			}, status=status.HTTP_400_BAD_REQUEST)
		
		except AuthForbidden as error:
			return Response({
				"error":"invalid token",
				"details": str(error)
			}, status=status.HTTP_400_BAD_REQUEST)
 
		if authenticated_user and authenticated_user.is_active:
			#generate JWT token
			login(request, authenticated_user)
			refresh = RefreshToken.for_user(user)
			data={
				# "token": jwt_encode_handler(
				#     jwt_payload_handler(user))
				"token": str(refresh.access_token)
				}
			#customize the response to your needs
			response = {
				"email": authenticated_user.email,
				"username": authenticated_user.username,
				"token": data.get('token')
			}
			return Response(status=status.HTTP_200_OK, data=response)
