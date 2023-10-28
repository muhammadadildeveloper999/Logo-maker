from rest_framework import serializers
import Usable.usable as uc
from .models import *
from passlib.hash import django_pbkdf2_sha256 as handler


class loginSerilizer(serializers.ModelSerializer):
    class Meta:
        model = SuperAdmin
        fields = '__all__'

    
    def validate(self, data):
        ##reqyuired keys and data not empty validation
        validator = uc.keyValidation(True,True,self.context['request'].data,self.context['requireFields'])
        if validator:
            raise serializers.ValidationError({"error":validator["message"]})
        
        ##email validation
        if not uc.checkemailforamt(data['email']):
            raise serializers.ValidationError({"error":"email is not valid"})

        return data



# import svgwrite

# class SVGSerializer(serializers.Serializer):
#     def generate_svg(self):
#         # Create an SVG drawing
#         svg_document = svgwrite.Drawing(profile='tiny')

#         # Add SVG elements
#         svg_document.add(svg_document.rect(insert=(10, 10), size=("100px", "100px"), fill='red'))
#         svg_document.add(svg_document.circle(center=(150, 150), r=50, fill='blue'))

#         return svg_document.tostring()
class SVGModelSerializer(serializers.ModelSerializer):
    class Meta:
        model = SVGModel
        fields = '__all__'