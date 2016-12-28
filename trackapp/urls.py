from django.conf.urls import  url,include

from rest_framework.authtoken import views
from trackapp.views import LoginView,AuthView,Login,AddUser,UserList,UsrViewSet,UList,ResetPassword,ConfirmPassword
from trackapp.views import GeodataList2, GeodataDetail,GeodataList
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
    url(r'^ulist/$', UList.as_view(), name='UList'),


    #***********************Token urls***************************
    #url(r'^test/', views.TestView.as_view(), name='test-view'),
    url(r'^auth/', AuthView.as_view(), name='auth-view'),
    url(r'^login_api/', Login.as_view(), name='auth-login'),

    #++++++++++++Reset paswod*****************************
    url(r'^ResetPassword/(?P<reset_id>[\w\+]+)/$',ResetPassword.as_view()),
    url(r'^ConfirmPassword/(?P<reset_id>[\w\+]+)/$',ConfirmPassword.as_view()),

    #*******************************File upload****************
    #url(r'^upload/$', views.SaveProfile, name='profile'),

    #url(r'^profile/',TemplateView.as_view(template_name = 'profile.html')),
    #url(r'^saved/', 'SaveProfile', name = 'saved'),


    # JSON data query response
    url(r'^gpsJSONdata/(?P<user_id>[0-9]+)/(?P<year>[0-9]+)/(?P<month>[0-9]+)/(?P<day>[0-9]+)/$',GeodataList2.as_view()),
    url(r'^gpsJSONData/(?P<pk>[0-9]+)/$', GeodataDetail.as_view()),

    # url for JSON data reciever
    url(r'^tracking/$', GeodataList.as_view()),
    url(r'^tracking/(?P<pk>[0-9]+)/$', GeodataDetail.as_view()),
]
