from django.db import models

# Create your models here.
from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager, PermissionsMixin
from django.db import models
from rest_framework_simplejwt.tokens import RefreshToken
import random
import os
from django.core.validators import RegexValidator

class UserManager(BaseUserManager):

    def create_user(self, username, email, password):
        if username is None:
            raise TypeError('Users should have a username')
        if password is None:
            raise TypeError('Users should have a password')

        user = self.model(username=username,email=email)
        user.set_password(password)
        user.save()
        return user

    def create_superuser(self, username, email, password):
        if password is None:
            raise TypeError('Password should not be none')

        user = self.create_user(username, email, password)
        user.is_superuser = True
        user.is_staff = True
        user.save()
        return user


def upload_image_path_profile(instance, filename):
	new_filename = random.randint(1,9996666666)
	name, ext = get_filename_ext(filename)
	final_filename = '{new_filename}{ext}'.format(new_filename=new_filename, ext=ext)
	return "Profile/{new_filename}/{final_filename}".format(
			new_filename=new_filename,
			final_filename=final_filename
	)
		 

def get_filename_ext(filepath):
	base_name = os.path.basename(filepath)
	name, ext = os.path.splitext(base_name)
	return name, ext


class CustomUser(AbstractUser):
	id = models.BigAutoField(auto_created=True, primary_key=True, serialize=True, verbose_name='ID')
	username = models.CharField('username',unique=True, max_length=255, blank=False,null=False)
	email = models.EmailField('email address', max_length=255, blank=True,null=True)
	full_name = models.CharField('Full Name', max_length=255, blank=True,
								  null=False)
	photo   = models.ImageField(default = 'static/default_image/default.png', upload_to = upload_image_path_profile, blank = True)
	country_code  = models.IntegerField(default=91, help_text='It is country code for calling',blank=True,null=True )
	phone_regex  = RegexValidator( regex   =r'^\d{9,15}$', message ="Phone number must be entered in the format: '+999999999'. Up to 14 digits allowed.")
	phone = models.CharField(validators=[phone_regex], max_length=17,blank=True)

	USERNAME_FIELD = 'username'

	def __str__(self):
		return f"{self.username}"
