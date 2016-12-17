
from django.shortcuts import HttpResponse
from trackapp.models import Usr
from rest_framework.views import APIView
import jwt
class JWT_AuthMiddleware(APIView):

    def _get_token(request=None):
        return request.META.get('HTTP_AUTHORIZATION') or request.POST.get('token')

    def process_request(self, request):
        token = self._get_token(request)
        try:
            payload = jwt.decode(token, 'secret')
            usr = Usr.objects.get(
                pk=payload.get('id'),
                is_active=True
            )
            return usr
        except jwt.ExpiredSignature:
            return HttpResponse({'Error': "Token is invalid"}, status="403")
        except jwt.DecodeError:
            return HttpResponse({'Error': "Token is invalid"}, status="403")
        except jwt.InvalidTokenError:
            return HttpResponse({'Error': "Token is invalid"}, status="403")
        except Usr.DoesNotExist:
            return HttpResponse({'Error': "Internal server error"}, status="500")