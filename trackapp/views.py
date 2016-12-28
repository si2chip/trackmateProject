from django.shortcuts import render, redirect

from trackapp.serializers import UsrSerializer, PasswordResetSerializer, GeodataSerializer
from trackapp.permissions import IsUsrOwner
from django.http import Http404
from django.core import serializers
from trackapp.jwtuserauth import JWT_AuthMiddleware
from django.core.mail import EmailMessage



from django.contrib.auth import authenticate, login, logout
from django.shortcuts import HttpResponse,render
from rest_framework import status, views

from rest_framework import permissions, viewsets
from rest_framework import generics

from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated
import jwt,json,pickle



################################Token import#########################
from rest_framework import parsers, renderers
from rest_framework.authtoken.models import Token
from rest_framework.authtoken.serializers import AuthTokenSerializer
from rest_framework.response import Response
from rest_framework.views import APIView



#-*- coding: utf-8 -*- here import moduls and forms for Email
from trackapp.models import Usr, Geodata
from trackapp.forms import ProfileForm
from trackapp.models import Profile
import uuid
import random

"""
Rest end point class based for Login using username password
"""

class LoginView(APIView):
    def post(self, request, format=None):

        #data = json.loads(request.body)

        email = request.data.get('email', '')
        password = request.data.get('password', '')

        usr = authenticate(email=email, password=password)
        # email = request.data.get('username', '')
        # password = request.data.get('password', '')

        print("user_data",email,"email",password)



        print("usr is active",usr)
        if usr is not None:
            if usr.is_active:
                login(request, usr)

                serialized = UsrSerializer(usr)

                return Response(serialized.data)
            else:
                return Response({
                    'status': 'Unauthorized',
                    'message': 'This usr has been disabled.'
                }, status=status.HTTP_401_UNAUTHORIZED)
        else:
            return Response({
                'status': 'Unauthorized',
                'message': 'Username/password combination invalid.'
            }, status=status.HTTP_401_UNAUTHORIZED)




"""
Add new user using Token Authentication (Django rest Framwork Token Auth)
"""

class AddUser(viewsets.ModelViewSet):
    """
    Authentication is needed for this methods
    """
    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)


    lookup_field = 'username'
    queryset = Usr.objects.all()
    serializer_class = UsrSerializer



    def get_permissions(self):

        if self.request.method in permissions.SAFE_METHODS:
            return (permissions.IsAuthenticated(),)

        if self.request.method == 'POST':
            return (permissions.IsAdminUser(),)


        return (permissions.IsAuthenticated(), IsUsrOwner(),)

    def create(self, request):
        serializer = self.serializer_class(data=request.data)

        if serializer.is_valid():
            #Usr.objects.create_user(**serializer.validated_data)
            serializer.is_valid(raise_exception=True)

            serializer.save()


            #genrating UUID and save in database
            user=Usr.objects.get(email=serializer.data.get('email'))
            user.reset_id=str(uuid.uuid1().hex)

            user.save()
            #sending Email
            html_content = "Please click on the link for reset password"
            url='http://192.168.0.175/ResetPassword/'+str(user.reset_id)
            email = EmailMessage("Subject", url, "suresh.si2chip@gmail.com", [user.email,"suresh.saini@si2chip.com"])
            email.content_subtype = "html"
            res=email.send()


            return Response(serializer.validated_data, status=status.HTTP_201_CREATED)


        return Response({
            'status': 'Bad request',
            'message': 'Usr could not be created with received data.'
        }, status=status.HTTP_400_BAD_REQUEST)


"""
GET list of users using Token Authenticaton
"""

class UsrViewSet(viewsets.ModelViewSet):
    """
    Authentication is needed for this methods
    """
    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)

    #lookup_field = 'username'
    queryset = Usr.objects.all()

    serializer_class = UsrSerializer
    print("jah hind",serializer_class.data)
    def get_permissions(self):
        if self.request.method in permissions.SAFE_METHODS:

            return (permissions.IsAuthenticated(),)


        return (permissions.IsAuthenticated(), IsUsrOwner(),)


"""
Usrer list without auth
"""

class UList(generics.ListCreateAPIView):
    queryset = Usr.objects.all()
    serializer_class = UsrSerializer
    # serializer=serializer_class(queryset)
    # print(serializer.data)


"""
Add new user using Token Authentication (Django rest Framwork Token Auth)
"""


class UsrDetail(APIView):
    """
    Retrieve, update or delete a snippet instance.
    """
    def get_object(self, email):
        try:
            return Usr.objects.get(email=email)
        except Usr.DoesNotExist:
            raise Http404


    def put(self, request, email, format=None):
        usr = self.get_object(email)
        serializer = UsrSerializer(usr, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, email, format=None):
        snippet = self.get_object(email)
        snippet.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)






"""
Reset password : Click on mail link then this api will hit for reset  password and
redirect to password reset page
"""

class ResetPassword(APIView):
    """
    Reset password app
    """
    def get(self, request,reset_id, format=None):
        try:
            user = Usr.objects.get(reset_id=reset_id)

            serializer = UsrSerializer(user)

            key=serializer.data.get('reset_id')

            if user is not None:

                return Response(serializer.data)

        except Exception:
            return HttpResponse("null")

        return HttpResponse("WOrofsjdnj")


    def post(self, request, format=None):
        serializer = UsrSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


"""
THis class for confirm reset password send by client.. Client will
do put request for reset password
"""

class ConfirmPassword(APIView):
    """
    Retrieve, update or delete a snippet instance.
    """
    def get_object(self, reset_id):
        try:
            return Usr.objects.get(reset_id=reset_id)
        except Usr.DoesNotExist:
            raise Http404

    def put(self, request, reset_id, format=None):

        user = self.get_object(reset_id)

        serializer = PasswordResetSerializer(user, data=request.data)

        if serializer.is_valid():

            serializer.save()
            try:
                user = Usr.objects.get(reset_id=serializer.data.get('reset_id'))
                password = serializer.data.get('password')
                user.set_password(password)
                user.reset_id=str(uuid.uuid1().hex)
                user.save()
                return Response("password is updated")
            except Exception:
                return Response("Your request is expired", status=status.HTTP_400_BAD_REQUEST)


        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, reset_id, format=None):
        user = self.get_object(reset_id)
        user.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

"""
This class for Forget passwrd when client request to forget get passwod
. THis end point send mail to client for change password
"""

class ForgetPassword(APIView):

    def post(self, request, format=None):

        email=request.POST.get("email")

        return Response(status=status.HTTP_400_BAD_REQUEST)






    """
    Login rest end point and respose Token to client
    Its class based and Token genrated by third partu module
    """


#***********************Token Based******************************

class Login(APIView):

    def post(self, request, *args, **kwargs):
        username = request.data.get('username')
        password = request.data.get('password')
        print("sfnjsfjsfjhshjsbfhjsbhjsb",username)
        user = authenticate(username=username, password=password)

        if user:
            payload = {
                'id': user.pk,
                'email': user.email,

            }
            encoded = jwt.encode(payload, 'secret', algorithm='HS256')

            token = {'Token': str(encoded)}

            tdata=json.dumps(token)
            return HttpResponse(
                tdata,
              content_type="application/json"
            )
        else:
            return HttpResponse(
              json.dumps({'Error': "Invalid credentials"}),
              status=400,
              content_type="application/json"
            )

"""
Django rest end point for get data with Token Authenticatiom(Django Token Auth Test)
"""
class AuthView(APIView):
    """
    Authentication is needed for this methods
    """
    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)

    def get(self, request, format=None):
        return Response({'detail': "I suppose you are authenticated"})


"""
GEt Users list using third party Token authentication
"""
class UserList(APIView):
    """
    Authentication is needed for this methods
    """

    def get(self, request, format=None):
        token = request.data.get('Token')
        print("msdjfgsjgfhjsgfhj")
        print(request.data)
        print(self.request.META.get('content-type', None))

        print("token",token)
        if token:
            try:
                payload = jwt.decode(token, 'secret')
                usr = Usr.objects.all()
                #usr = Usr.objects.filter(pk=payload.get('id'),is_active=True)
                serializer = UsrSerializer(usr, many=True)
                return Response(serializer.data)

            except jwt.ExpiredSignature:
                return HttpResponse({'Error': "Token is invalid"}, status="403")
            except jwt.DecodeError:
                return HttpResponse({'Error': "Token is invalid"}, status="403")
            except jwt.InvalidTokenError:
                return HttpResponse({'Error': "Token is invalid"}, status="403")
            except Usr.DoesNotExist:
                return HttpResponse({'Error': "Internal server error"}, status=500)

        return HttpResponse({'Error': "Token is invalid"}, status="403")


"""
#  class based views for Geodata model--------------------------------------------
"""

class GeodataList(APIView):
    """
    List all Geodata, or create a new Geodata.
    """
    def get(self, request, format=None):
        geodata = Geodata.objects.filter()
        serializer = GeodataSerializer(geodata, many=True)
        return Response(serializer.data)
   # parser_classes = (JSONParser,)
    def post(self, request, format=None):
        serializer = GeodataSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class GeodataList2(APIView):
    """
    List all Geodata, or create a new Geodata.
    """
    def get(self, request,user_id,year,month,day, format=None):
        geodata = Geodata.objects.filter(user_id__contains=user_id,time_stamp__year=year,time_stamp__month=month,time_stamp__day=day)
        serializer = GeodataSerializer(geodata, many=True)
        return Response(serializer.data)
   # parser_classes = (JSONParser,)
    def post(self, request, format=None):
        serializer = GeodataSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class GeodataDetail(APIView):
    """
    Retrieve, update or delete a Geodata instance.
    """
    def get_object(self,pk):
        try:
            return Geodata.objects.filter(pk=pk)
        except Geodata.DoesNotExist:
            raise Http404

    def get(self, request,pk, format=None):
        geodata = self.get_object(pk)
        serializer = GeodataSerializer(geodata)
        return Response(serializer.data)

    def put(self, request,pk, format=None):
        geodata = self.get_object(pk)
        serializer = GeodataSerializer(geodata, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk, format=None):
        geodata = self.get_object(pk)
        geodata.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

#------------------------------------end.........................................................






"""
Method for upload file and send Email to any Client
"""

def SaveProfile(request):
    saved = False

    if request.method == "POST":
        # Get the posted form
        MyProfileForm = ProfileForm(request.POST, request.FILES)
        print("sdfsfsfsfsf")
        if MyProfileForm.is_valid():
            profile = Profile()
            profile.name = MyProfileForm.cleaned_data["name"]
            profile.picture = MyProfileForm.cleaned_data["picture"]
            print("fsfsfsfsf",profile.picture)
            html_content = "Comment tu vas?"
            email = EmailMessage("Subject", profile.name, "suresh.si2chip@gmail.com", ["suresh.saini@si2chip.com"])
            email.content_subtype = "html"

            email.attach(profile.picture.name, profile.picture.read())


            res = email.send()
            profile.save()
            saved = True
            return render(request, 'trackapp/save.html', locals())
    else:
        #MyProfileForm = Profileform()
        return render(request, 'trackapp/profile.html', locals())

    return render(request, 'trackapp/profile.html', locals())



