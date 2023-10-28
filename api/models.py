from django.db import models
import uuid

# Create your models here.

class BaseModel(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False,max_length=255)
    updated_at = models.DateTimeField(auto_now_add=True,blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True,blank=True, null=True)


    # updated_at = models.DateTimeField(blank=True, null=True)
    # created_at = models.DateTimeField(blank=True, null=True)
    class Meta:
        abstract = True


class SuperAdmin(BaseModel):
    
    user_role =(
        ("superadmin", "superadmin"),
        ("manager", "manager"),
    
    )

    fname=models.CharField(max_length=255, default="")
    lname=models.CharField(max_length=255, default="")
    address=models.TextField(default="")
    email=models.EmailField(max_length=255, default="")
    password=models.TextField(default="")
    contact=models.CharField(max_length=20, default="")
    profile= models.ImageField(upload_to='SuperAdmin/',default="SuperAdmin/dummy.jpg")
    Otp = models.IntegerField(default=0)
    OtpCount = models.IntegerField(default=0)
    OtpStatus = models.BooleanField(default=False)
    no_of_attempts_allowed = models.IntegerField(default=3)
    no_of_wrong_attempts = models.IntegerField(default=0)
    status = models.BooleanField(default=True)
    role = models.CharField(choices = user_role,max_length=10,default="superadmin")

    
    def __str__(self):
        return self.email



class whitelistToken(BaseModel):
    user = models.ForeignKey(SuperAdmin, on_delete =models.CASCADE)
    token = models.TextField(default="")
    created_at = models.DateTimeField(auto_now_add=True,blank=True, null=True)
   


class SVGModel(BaseModel):
    svg_file = models.FileField(upload_to='svg_files/')
    svg_content = models.TextField(default="")