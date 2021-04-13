from django.contrib.auth import get_user_model, password_validation
from rest_framework.authtoken.models import Token
from rest_framework import serializers
from django.contrib.auth.models import BaseUserManager
from django.contrib.auth.password_validation import validate_password
from django.core.validators import RegexValidator
import os
from rest_framework.exceptions import AuthenticationFailed
from .models import CustomUser

User = get_user_model()

from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework.validators import UniqueValidator

class MyTokenObtainPairSerializer(TokenObtainPairSerializer):

    @classmethod
    def get_token(cls, user):
        token = super(MyTokenObtainPairSerializer, cls).get_token(user)

        # Add custom claims
        token['username'] = user.username
        return token

class ChangePasswordSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
    password2 = serializers.CharField(write_only=True, required=True)
    old_password = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = CustomUser
        fields = ('old_password', 'password', 'password2')

    def validate(self, attrs):
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError({"password": "Password fields didn't match."})

        return attrs

    def validate_old_password(self, value):
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError({"old_password": "Old password is not correct"})
        return value

    def update(self, instance, validated_data):

        instance.set_password(validated_data['password'])
        instance.save()

        return instance


class UserLoginSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=255, required=True)
    email = serializers.CharField(max_length=255, required=False)
    password = serializers.CharField(required=True, write_only=True)



class AuthUserSerializer(serializers.ModelSerializer):

    class Meta:
         model = CustomUser
         fields = ('id','username', 'email','full_name','photo' ,'country_code','phone','is_active', 'is_staff')
         read_only_fields = ('id', 'is_active', 'is_staff')
    

class EmptySerializer(serializers.Serializer):
    pass


class UserRegisterSerializer(serializers.ModelSerializer):
    """
    A user serializer for registering the user
    """

    class Meta:
        model = CustomUser
        fields = ('id', 'username','email', 'password', 'full_name','photo','country_code','phone')

    def validate_username(self, value):
        user = CustomUser.objects.filter(username='username')
        if user:
            raise serializers.ValidationError("username is already taken")
        return value
    def validate_phone(self, value):
        user = CustomUser.objects.filter(phone='phone')
        if user:
            raise serializers.ValidationError("username with this phone number is already taken")
        return value
    # def validate_email(self, value):
    #     user = CustomUser.objects.filter(email='email')
    #     if user:
    #         raise serializers.ValidationError("username with this email is already taken")
    #     return BaseUserManager.normalize_email(value)

    def validate_password(self, value):
        password_validation.validate_password(value)
        return value

    def create(self, validated_data):
        
        user = User(**validated_data)
        user.set_password(validated_data['password'])
        user.save()
        # print(user,"##################")
        user.save()
        
        return user

    # def create(self, validated_data):
        # user = CustomUser.objects.create(
        #     username=validated_data['username'],
        #     email=validated_data['email'],
        #     full_name=validated_data['full_name'],
        #     photo=validated_data['photo'],
        #     phone = validated_data['phone'],
        #     country_code=validated_data['country_code']
        # )

        
        # user.set_password(validated_data['password'])
        # user.save()

        # return user

class UpdateUserSerializer(serializers.ModelSerializer):

    class Meta:
        model = User
        fields = ('username','full_name', 'photo','email','phone','country_code')

    def validate_email(self, value):
        user = self.context['request'].user
        if User.objects.exclude(pk=user.pk).filter(email=value).exists():
            raise serializers.ValidationError({"email": "This email is already in use."})
        return value

    def validate_username(self, value):
        user = self.context['request'].user
        if User.objects.exclude(pk=user.pk).filter(username=value).exists():
            raise serializers.ValidationError({"username": "This username is already in use."})
        return value
    def validate_phone(self, value):
        user = self.context['request'].user
        if User.objects.exclude(pk=user.pk).filter(phone=value).exists():
            raise serializers.ValidationError({"phone:  This phone number is already in use"})
        return value

    def update(self, instance, validated_data):
        instance.full_name = validated_data['full_name']
        instance.photo = validated_data['photo']
        instance.email = validated_data['email']
        instance.username = validated_data['username']
        instance.phone = validated_data['phone']
        instance.country_code = validated_data['country_code']
        instance.save()

        return instance


class PhoneOtpGenerate(serializers.Serializer):
    phone_regex  = RegexValidator(regex=r'^\d{9,12}$', message="phone_number ,must enter in format +999999999 upto 10 digits")
    country_code = serializers.IntegerField(required=True)
    phone_number = serializers.CharField(validators=[phone_regex],required=True)



class ValidateOTP(serializers.Serializer):
    phone_regex  = RegexValidator(regex=r'^\d{9,12}$', message="phone_number ,must enter in format +999999999 upto 10 digits")
    country_code = serializers.IntegerField(required=True)
    phone = serializers.CharField(validators=[phone_regex],required=True)
    otp = serializers.IntegerField()


class SocialSerializer(serializers.Serializer):

    provider = serializers.CharField(max_length=255, required=True)
    access_token = serializers.CharField(max_length=4096, required=True, trim_whitespace=True)