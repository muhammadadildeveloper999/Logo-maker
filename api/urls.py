from django.urls import path,include
from api.views import *
from . import views

urlpatterns = [

#superadmin
path('',index),
path('superadmin/login',superadminlogin.as_view()),
path('superadmin/logout',superadminlogout.as_view()),
path('superadmin/profile',superadminprofile.as_view()),
path('superadmin/changepassword',superadminchangepassword.as_view()),
path('superadmin/forgotPasswordlinkSend',superadminforgotPasswordlinkSend.as_view()),
path('superadmin/forgettokenCheck',superadminforgettokenCheck.as_view()),
path('superadmin/forgetConfirmation',superadminforgetConfirmation.as_view()),

# path('generate-svg/', views.generate_svg, name='generate-svg'),
path('svg/', SVGListCreateView.as_view()),
path('svg-get/', SVGRenderView.as_view()),



 
]
