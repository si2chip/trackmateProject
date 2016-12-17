from trackapp.serializers import UsrSerializer
from trackapp.permissions import IsUsrOwner
from django.core import serializers
from trackapp.jwtuserauth import JWT_AuthMiddleware



from django.contrib.auth import authenticate, login, logout
from django.shortcuts import HttpResponse
from rest_framework import status, views
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import permissions, viewsets


from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated
import jwt,json,pickle

from trackapp.models import Usr

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

            token = {'Token': encoded}
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


class AuthView(APIView):
    """
    Authentication is needed for this methods
    """
    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)

    def get(self, request, format=None):
        return Response({'detail': "I suppose you are authenticated"})

class AddUser(viewsets.ModelViewSet):
    """
    Authentication is needed for this methods
    """
    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)


    lookup_field = 'username'
    queryset = Usr.objects.all()
    serializer_class = UsrSerializer
    #print("jah hind",serializer_class.data)
    def get_permissions(self):

        if self.request.method in permissions.SAFE_METHODS:
            return (permissions.IsAuthenticated(),)

        if self.request.method == 'POST':
            return (permissions.IsAdminUser(),)

        return (permissions.IsAuthenticated(), IsUsrOwner(),)

    def create(self, request):
        serializer = self.serializer_class(data=request.data)

        if serializer.is_valid():
            Usr.objects.create_user(**serializer.validated_data)

            return Response(serializer.validated_data, status=status.HTTP_201_CREATED)

        return Response({
            'status': 'Bad request',
            'message': 'Usr could not be created with received data.'
        }, status=status.HTTP_400_BAD_REQUEST)


    # def get(self, request, format=None):
    #     usr = Usr.objects.all()
    #     serializer = UsrSerializer(usr, many=True)
    #     return Response(serializer.data)

    # def post(self, request, format=None):
    #     serializer = UsrSerializer(data=request.data)
    #     if serializer.is_valid():
    #         serializer.save()
    #         return Response(serializer.data, status=status.HTTP_201_CREATED)
    #     return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserList(APIView):
    """
    Authentication is needed for this methods
    """

    def get(self, request, format=None):
        token = request.data.get('Token')
        print(request.data)
        print(self.request.META.get('content-type', None))

        print("token",token)
        if token:
            try:
                payload = jwt.decode(token, 'secret')

                usr = Usr.objects.filter(pk=payload.get('id'),is_active=True)
                serializer = UsrSerializer(usr, many=True)
                return Response(serializer.data)

            except jwt.ExpiredSignature:
                return HttpResponse({'Error': "Token is invalid"}, status="403")
            except jwt.DecodeError:
                return HttpResponse({'Error': "Token is invalid"}, status="403")
            except jwt.InvalidTokenError:
                return HttpResponse({'Error': "Token is invalid"}, status="403")
            except Usr.DoesNotExist:
                return HttpResponse({'Error': "Internal server error"}, status="500")

        return HttpResponse({'Error': "Token is invalid"}, status="403")



