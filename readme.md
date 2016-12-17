from django.db import models

from django.contrib.auth.models import AbstractBaseUser
from django.contrib.auth.models import BaseUserManager

class UsrManager(BaseUserManager):
    def create_user(self, email, password=None, **kwargs):
        if not email:
            raise ValueError('Users must have a valid email address.')

        if not kwargs.get('username'):
            raise ValueError('Users must have a valid username.')

        usr = self.model(
            email=self.normalize_email(email), username=kwargs.get('username')
        )

        usr.set_password(password)
        usr.save()

        return usr

    def create_superuser(self, email, password, **kwargs):
        usr = self.create_user(email, password, **kwargs)

        usr.is_admin = True
        usr.save()

        return usr

class Usr(AbstractBaseUser):
    username = models.CharField(max_length=40, unique=True)
    email = models.EmailField(unique=True)

    first_name = models.CharField(max_length=40, blank=True)
    last_name = models.CharField(max_length=40, blank=True)
    designation = models.CharField(max_length=140, blank=True)
    #edit here for Address and others fields

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    #edit here for
    is_admin = models.BooleanField(default=False)
    #is_supportEngineer = models.BooleanField(default=False)


    objects = UsrManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    def __unicode__(self):
        return self.email

    def get_full_name(self):
        return ' '.join([self.first_name, self.last_name])

    def get_short_name(self):
        return self.first_name




from django.conf.urls import url

from . import views

urlpatterns = [

    url(r'^home/$', views.home, name='home'),
]



{
        "email": "suresh.si2chip@gmail.com",
        "password": "bharat12345"
    
    }
{
        "email": "suresh.saini@si2chip.com",
        "password": "bharat12345"
    
    }


{
        "email": "sushvision22@gmail.com",
        "password": "bharat12345"
    
    }

