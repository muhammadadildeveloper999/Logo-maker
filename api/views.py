from rest_framework.views import APIView
from rest_framework.response import Response
from passlib.hash import django_pbkdf2_sha256 as handler
from datetime import datetime
from django.http import HttpResponse
from .serilizer import *
from django.db.models import F,Sum,Q,Count
from decouple import config
from django.conf import settings
from Usable.permissions import authorization
from operator import itemgetter
import Usable.emailpattern as verfied
import random
from rest_framework import status



# Create your views here.
def index(request):
    return HttpResponse("<h1>Project-Logo-Maker</h1>")

class superadminlogin(APIView):
    def post(self,request):
        try:
            requireFields = ['email','password']
            val = loginSerilizer(data = request.data,context = {'request':request,"requireFields":requireFields})
            if val.is_valid():
                email = request.data['email']
                password = request.data['password']
                
                fetchuser = SuperAdmin.objects.filter(email = email,role = "superadmin").first()

                if fetchuser and handler.verify(password,fetchuser.password):
                    
                    jwtkeys = {"superadmin":config("superadminjwttoken")} 
                    generate_auth = uc.generatedToken(fetchuser,jwtkeys[fetchuser.role],1,request)
                            
                    if generate_auth['status']:
                        fetchuser.no_of_wrong_attempts = 0
                        fetchuser.save()
                        return Response({'status':True,'message':'Login SuccessFully','token':generate_auth['token'],'data':generate_auth['payload']},status=200)

                    else:
                        return Response(generate_auth)


                

                else:
                    if fetchuser:
                        if fetchuser.no_of_wrong_attempts == fetchuser.no_of_attempts_allowed:
                            fetchuser.status = False
                        else:
                            fetchuser.no_of_wrong_attempts+=1

                        fetchuser.save()
                        if not fetchuser.status:
                            return Response({'status':False,'message':'Your Account is disable'},403)


                        
                    return Response({'status':False,'message':'Invalid Credential'},status = 401)

            
            else:
                error = uc.execptionhandler(val)
                return Response({'status':False,'message':error},status=422)



        except Exception as e:
            message = {'status':False}
            message.update(message=str(e))if settings.DEBUG else message.update(message='Internal server error')
            return Response(message,status=500)




class superadminlogout(APIView):
    permission_classes = [authorization]

    def get(self,request):
        try:
            res = {True:{"status":True,"message":"logout successfully"},False:{"status":False,"message":"Something went wrong"}}
            
            fetch = uc.blacklisttoken(request.GET['token']['id'],request.META['HTTP_AUTHORIZATION'][7:])
            return Response(res[fetch])



        except Exception as e:
            message = {'status':False}
            message.update(message=str(e))if settings.DEBUG else message.update(message='Internal server error')
            return Response(message,status=500)



class superadminprofile(APIView):
    permission_classes = [authorization]

    def get(self,request):
        try:
            fetchuser = SuperAdmin.objects.filter(id = request.GET['token']['id']).first()
            access_token_payload = {
                "id":fetchuser.id,
                "fname":fetchuser.fname,
                "lname":fetchuser.lname,
                "email":fetchuser.email,
                "profile":fetchuser.profile.url,
                "address":fetchuser.address,
                "contact":fetchuser.contact
            }

            return Response({"status":True,"data":access_token_payload})


        except Exception as e:
            message = {'status':False}
            message.update(message=str(e))if settings.DEBUG else message.update(message='Internal server error')
            return Response(message,status=500)


    
    def put(self,request):
        try:
            requireFields = ['fname','lname','address','contact']
            validator = uc.keyValidation(True,True,request.data,requireFields)
            if validator:
                return Response(validator,status = 422)

            else:
                fetchuser = SuperAdmin.objects.filter(id = request.GET['token']['id']).first()
                fetchuser.fname, fetchuser.lname,fetchuser.address, fetchuser.contact = itemgetter('fname', 'lname','address','contact')(request.data)


                if request.FILES.get('img',False):
                    if not uc.imageValidator(request.FILES['img'],False,False):
                        return Response({'status':False,"message":"Image format is incorrect"},422)
                    
                    fetchuser.profile = request.FILES['img']

                fetchuser.save()
                obj = uc.makedict(fetchuser,['id','fname','lname','address','contact','email','profile'],True)
                return Response({"status":True,"message":"Update Successfully","data":obj})



        except Exception as e:
            message = {'status':False}
            message.update(message=str(e))if settings.DEBUG else message.update(message='Internal server error')
            return Response(message,status=500)




class superadminchangepassword(APIView):
    permission_classes = [authorization]

    def post(self,request):
        try:
            requireFields = ['oldpassword','password']
            validator = uc.keyValidation(True,True,request.data,requireFields)
            if validator:
                return Response(validator,status = 200)

            else:
                data = SuperAdmin.objects.filter(id = request.GET['token']['id']).first()
                if handler.verify(request.data['oldpassword'],data.password):
                    ##check if user again use old password
                    if not handler.verify(request.data['password'],data.password):
                        
                        #password length validation
                        passwordStatus = uc.passwordLengthValidator(request.data['password'])
                        if not passwordStatus:
                            return Response({"status":False,"message":"Password must be 8 or less than 20 characters"})
                    
                        data.password = handler.hash(request.data['password'])
                        data.save()

                        ## black list token
                        uc.blacklisttoken(request.GET['token']['id'],request.META['HTTP_AUTHORIZATION'][7:])

                        ##Create new token
                        jwtkeys = {"superadmin":config("superadminjwttoken")} 
                        generate_auth = uc.generatedToken(data,jwtkeys[data.role],1,request)
                        return Response({'status':True,'message':'Password Update Successfully','token':generate_auth['token']})

                    else:
                        return Response({'status':False,'message':'You choose old password try another one'})


                else:
                    return Response({'status':False,'message':'Your Old Password is Wrong'})

    

        except Exception as e:
            message = {'status':False}
            message.update(message=str(e))if settings.DEBUG else message.update(message='Internal server error')
            return Response(message,status=500)




class superadminforgotPasswordlinkSend(APIView):
    def post(self,request):
        try:
            requireFields = ['email']
            validator = uc.keyValidation(True,True,request.data,requireFields)
            if validator:
                return Response(validator,status = 200)
                
            
            else:
                email = request.data['email']
                emailstatus = uc.checkemailforamt(email)
                if not emailstatus:
                    return Response({"status":False,"message":"Email format is incorrect"})

                fetchadmin = SuperAdmin.objects.filter(email = email).first()
                
                if fetchadmin:
                    if fetchadmin.status:
                        token=random.randrange(1000,100000,5)
                        fetchadmin.Otp = token
                        fetchadmin.OtpCount = 0
                        fetchadmin.OtpStatus = True
                        fetchadmin.save()
                        emailstatus = verfied.forgetEmailPattern({"subject":"forget password","EMAIL_HOST_USER":config('EMAIL_HOST_USER'),"toemail":email,"token":token})
                        if emailstatus:
                            return Response({'status':True,'message':"Email send successfully",'id':fetchadmin.id})

                        else:
                            return Response({'status':False,'message':'Something went wrong'})

                    
                    else:
                        return Response({'status':False,'message':'Your Account is disable'})
                
                else:
                    return Response({'status':False,'message':'Email doesnot exist'})

        
        except Exception as e:
            message = {'status':False}
            message.update(message=str(e))if settings.DEBUG else message.update(message='Internal server error')
            return Response(message,status=500)



class superadminforgettokenCheck(APIView):
    def post(self,request):
        try:
            ##validator keys and required
            requireFields = ['token','id']
            validator = uc.keyValidation(True,True,request.data,requireFields)
            
            if validator:
                return Response(validator,status = 200)
                

            else:
                token = request.data.get('token')
                adminid = request.data.get('id')
                checkExist = SuperAdmin.objects.filter(id = adminid).first()
                if checkExist:
                    if checkExist.OtpStatus and checkExist.OtpCount < 3:
                        if checkExist.Otp == int(token):
                            return Response({"status":True,"message":'Access Granted'})

                        else:
                            checkExist.OtpCount = checkExist.OtpCount + 1
                            checkExist.save()
                            return Response({'status':False,'message':'Your Otp is incorrect'})


                    else:
                        return Response({'status':False,'message':'Your Otp is expire'})

                else:
                    return Response({'status':False,'message':'Id is incorrect'})



        except Exception as e:
            message = {'status':False}
            message.update(message=str(e))if settings.DEBUG else message.update(message='Internal server error')
            return Response(message,status=500)


class superadminforgetConfirmation(APIView):
    def post(self,request):
        try:
            requireFields = ['password','adminid']
            validator = uc.keyValidation(True,True,request.data,requireFields)
            if validator:
                return Response(validator,status = 200)
            
            #Recive data 
            password = request.POST['password']
            adminid = request.POST['adminid']
            checkExist = SuperAdmin.objects.filter(id = adminid).first()
            
            if checkExist:
                ##Password Length Validator
                passwordStatus = uc.passwordLengthValidator(password)
                if not passwordStatus:
                    return Response({"status":False,"message":"Password must be 8 or less than 20 characters"})
            
                if checkExist.OtpStatus:
                    checkExist.password = handler.hash(password)
                    checkExist.OtpStatus = False
                    checkExist.save()

                    ## Blacklist all the tokens
                    fetchtokens = whitelistToken.objects.filter(user = checkExist)
                    if fetchtokens:
                        fetchtokens.delete()

                    return Response({'status':True,'message':'Password Update Successfully'})

                else:
                    return Response({'status':False,'message':'Token is expire'})
                    


            else:
                return Response({'status':False,'message':'Id is incorrect'})


        except Exception as e:
            message = {'status':False}
            message.update(message=str(e))if settings.DEBUG else message.update(message='Internal server error')
            return Response(message,status=500)


########################################################
from django.http import HttpResponse
import svgwrite

# def generate_svg(request):
#     # Create an SVG drawing
#     svg_document = svgwrite.Drawing(filename="example.svg", profile='tiny')

#     # Add SVG elements
#     svg_document.add(svg_document.rect(insert=(10, 10), size=("100px", "100px"), fill='red'))
#     svg_document.add(svg_document.circle(center=(150, 150), r=50, fill='blue'))

#     # Return the SVG content as HTTP response
#     response = HttpResponse(content_type='image/svg+xml')
#     svg_document.write(response)
#     return response



# class SVGViewSet(APIView):

    # def get(self, request):
    #     serializer = self.get_serializer()
    #     svg_content = SVGSerializer.generate_svg()
    #     return Response({'svg_content': svg_content})

    # serializer_class = SVGSerializer

    # def get(self, request):
    #     # serializer = self.get_serializer()
    #     svg_content = SVGSerializer.generate_svg(self)
    #     return Response({'svg_content': svg_content})

class SVGListCreateView(APIView):

    def get(self, request):
        svg_instances = SVGModel.objects.all()
        serializer = SVGModelSerializer(svg_instances, many=True)
        return Response(serializer.data)
    
    def post(self, request):
        serializer = SVGModelSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    


# class SVGRenderView(APIView):
#     def get(self, request):
#         try:
#             id = request.GET['id']
#             svg_instance = SVGModel.objects.get(id=id)
#             svg_file = svg_instance.svg_file
#             with open(svg_file.path, 'rb') as f:
#                 # response = HttpResponse(f.read(), content_type='image/svg+xml')
#                 response = Response({"status":True, "data":f.read()})
#                 # print("response=========",response)
#                 # return response
#         except SVGModel.DoesNotExist:
#             return HttpResponse(status=404)


# class SVGRenderView(APIView):
#     def get(self, request):
#         try:
#             id = request.GET['id']
#             svg_instance = SVGModel.objects.get(id=id)
#             svg_file_path = svg_instance.svg_file.path
#             with open(svg_file_path, 'r') as f:
#                 svg_content = f.read()
#                 svg_content = svg_content.replace('\n', '').replace('\\','')
#                 # svg_content = str(svg_content)
#                 # svg_content = svg_content.replace('\n', '').replace("\ ".replace(" ", ""), "")
#                 # svg_content = svg_content.replace("\ ".replace(" ", ""), "")
                
#                 return Response({'svg_content': svg_content})
#         except SVGModel.DoesNotExist:
#             return HttpResponse(status=404)



class SVGRenderView(APIView):
    def get(self, request):
        try:
            id = request.GET['id']
            svg_instance = SVGModel.objects.get(id=id)
            svg_content = svg_instance.svg_content
            svg_content = svg_content.replace('\n', '').replace('\\','')

            
            return Response({'svg_content': svg_content})
        except SVGModel.DoesNotExist:
            return HttpResponse(status=404)