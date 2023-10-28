from rest_framework import permissions
from rest_framework.exceptions import APIException
from rest_framework import status
from decouple import config
import jwt
from api.models import whitelistToken


##Only for admin

class authorization(permissions.BasePermission):

    def has_permission(self, request, view):
        try:

           
            tokencatch = request.META['HTTP_AUTHORIZATION'][7:]
            request.GET._mutable = True
            my_token = jwt.decode(tokencatch,config('superadminjwttoken'), algorithms=["HS256"])
            request.GET['token'] = my_token
            whitelistToken.objects.get(user = my_token['id'],token = tokencatch)
            return True
            

        except:
            raise NeedLogin()




class NeedLogin(APIException):
    status_code = 401
    default_detail = {'status': False, 'message': 'Unauthorized'}
    default_code = 'not_authenticated'