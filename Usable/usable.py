import jwt
import datetime
import re
import random
from api.models import whitelistToken
from PIL import Image


def requireKeys(reqArray,requestData):
    try:
        for j in reqArray:
            if not j in requestData:
                return False
            
        return True

    except:
        return False


def allfieldsRequired(reqArray,requestData):
    try:
        for j in reqArray:
            if len(requestData[j]) == 0:
                return False

        
        return True

    except:
        return False


def checkemailforamt(email):
    emailregix = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'

    if(re.match(emailregix, email)):

        return True

    else:
       return False



def passwordLengthValidator(passwd):
    if len(passwd) >= 8 and len(passwd) <= 20:
        return True

    else:
        return False



##both keys and required field validation

def keyValidation(keyStatus,reqStatus,requestData,requireFields):


    ##keys validation
    if keyStatus:
        keysStataus = requireKeys(requireFields,requestData)
        if not keysStataus:
            return {'status':False,'message':f'{requireFields} all keys are required'}



    ##Required field validation
    if reqStatus:
        requiredStatus = allfieldsRequired(requireFields,requestData)
        if not requiredStatus:
            return {'status':False,'message':'All Fields are Required'}





def imageValidator(img,ignoredimension = True,formatcheck = False):

    try:

        if img.name[-3:] == "svg":
            return True
        im = Image.open(img)
        width, height = im.size
        if ignoredimension:
            if width > 330 and height > 330:
                return False

            else:
                return True

        if formatcheck:
            if im.format == "PNG":
                
                return True

            else:
                
                return False
            
        return True
    
    except:
        return False


def blacklisttoken(id,token):
    try:
        whitelistToken.objects.get(user = id,token = token).delete()
        return True
    
    except:
        return False


def generatedToken(fetchuser,authKey,totaldays,request):
    try:
        access_token_payload = {
            'id': str(fetchuser.id),
            'email':fetchuser.email,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=totaldays),
            'iat': datetime.datetime.utcnow(),

        }
        
        userpayload = { 'id': str(fetchuser.id),'email':fetchuser.email,'fname':fetchuser.fname,'lname':fetchuser.lname,'profile':fetchuser.profile.url,'role':fetchuser.role}
    
        access_token = jwt.encode(access_token_payload,authKey, algorithm='HS256')
        whitelistToken(user = fetchuser,token = access_token).save()
        return {"status":True,"token":access_token,"payload":userpayload}

    except Exception as e:
        return {"status":False,"message":"Something went wrong in token creation","details":str(e)}


def execptionhandler(val):
    if 'error' in val.errors:
        error = val.errors["error"][0]
    else:
        key = next(iter(val.errors))
        error = key + ", "+val.errors[key][0]

    return error




def makedict(obj,key,imgkey=False):
    dictobj = {}
    
    for j in range(len(key)):
        keydata = getattr(obj,key[j])
        if keydata:
            dictobj[key[j]] = keydata
    
    if imgkey:
        imgUrl = getattr(obj,key[-1])
        if imgUrl:
            dictobj[key[-1]] = imgUrl.url
        else:
             dictobj[key[-1]] = ""



  

    return dictobj
