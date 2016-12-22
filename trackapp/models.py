from django.db import models
from django.contrib.auth.models import AbstractBaseUser
from django.contrib.auth.models import BaseUserManager
from django.conf import settings
from django.db.models.signals import post_save
from django.dispatch import receiver
from rest_framework.authtoken.models import Token


# /***
# * UsrmManager class here overide django UserMaganer
# *
# */


class UsrManager(BaseUserManager):

    #override django BaseUserManager create_user method
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

    #override django BaseUserManager create_superuser method
    def create_superuser(self, email, password, **kwargs):
        usr = self.create_user(email, password, **kwargs)

        usr.is_admin = True
        usr.is_active = True
        usr.save()

        return usr


# /***
# * Usr class inherite Django User model
# *
# */

class Usr(AbstractBaseUser):
    username = models.CharField(max_length=40, unique=True)
    email = models.EmailField(unique=True)

    first_name = models.CharField(max_length=40, blank=True)
    last_name = models.CharField(max_length=40, blank=True)

    designation = models.CharField(max_length=140, blank=True)
    address = models.TextField(default='none',max_length=200,blank=True)
    contact = models.IntegerField(default=0000000,blank=True)
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

    def has_perm(self, perm, obj=None):
        "Does the user have a specific permission?"
        # Simplest possible answer: Yes, always
        return True

    def has_module_perms(self, app_label):
        "Does the user have permissions to view the app `app_label`?"
        # Simplest possible answer: Yes, always
        return True

    @property
    def is_staff(self):
        "Is the user a member of staff?"
        # Simplest possible answer: All ad
        return self.is_admin

"""
THis Model for Upload file and text
"""
class Profile(models.Model):
    name = models.CharField(max_length=50)
    picture = models.FileField()

    class Meta:
        db_table = "profile"

"""
This method for genrating Token
"""
#genratiing token here
@receiver(post_save, sender=settings.AUTH_USER_MODEL)
def create_auth_token(sender, instance=None, created=False, **kwargs):
    if created:
        Token.objects.create(user=instance)


