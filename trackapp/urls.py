from django.conf.urls import  url,include

from rest_framework.authtoken import views
from trackapp.views import LoginView,AuthView,Login,AddUser,UserList,UsrViewSet
from rest_framework import routers
#from . import views


router = routers.SimpleRouter()
router.register(r'adduser', AddUser)
router.register(r'userlist',UsrViewSet)

urlpatterns = [
    url(r'^api/v1/', include(router.urls)),
    url(r'^api-token-auth/', views.obtain_auth_token),
    url(r'^api/v1/auth/login/$', LoginView.as_view(), name='login'),
    #url(r'^api/v1/auth/adduser/$', AddUser.as_view(), name='AddUser'),
    url(r'^api/v1/auth/userlist/$', UserList.as_view(), name='UserList'),



    #***********************Token urls***************************
    #url(r'^test/', views.TestView.as_view(), name='test-view'),
    url(r'^auth/', AuthView.as_view(), name='auth-view'),
    url(r'^login_api/', Login.as_view(), name='auth-login'),

    #*******************************File upload****************
    #url(r'^upload/$', views.SaveProfile, name='profile'),

    #url(r'^profile/',TemplateView.as_view(template_name = 'profile.html')),
    #url(r'^saved/', 'SaveProfile', name = 'saved')
]
