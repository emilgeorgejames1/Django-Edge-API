from django.contrib.contenttypes.models import ContentType
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.auth import get_user_model
from django.db.models import Q



from rest_framework.serializers import (
    CharField,
    EmailField,
    HyperlinkedIdentityField,
    ModelSerializer,
    SerializerMethodField,
    ValidationError
)

from rest_framework.filters import (
        SearchFilter,
        OrderingFilter,
    )

User = get_user_model()


class UserCreateSerializer(ModelSerializer):

    class Meta:
        model = User
        fields = ['email', 'name', 'password']
        # fields = '__all__'
        extra_kwargs = {"password":
                        {"write_only": True}
                        }

    def create(self, validated_data):
        password = validated_data.pop('password', None)
        instance = self.Meta.model(**validated_data)
        if password is not None:
            instance.set_password(password)
        instance.save()
        return instance

    def update(self, instance, validated_data):
        for attr, value in validated_data.items():
            if attr == 'password':
                instance.set_password(value)
            else:
                setattr(instance, attr, value)
        instance.save()
        return instance  
        
       

class UserLoginSerializer(ModelSerializer):
    token = CharField(allow_blank=True,read_only=True)
    email = EmailField(label='Email Address',required=False,allow_blank=True)
    class Meta:
        model = User
        fields = [
             'email',
             'password',
             'token',

        ]
        extra_kwargs = {"password":
                        {"write_only": True}
                        }
    
    def validate(self,data):
        user_obj = None
        email = data.get("email",None)
        password = data["password"]
        if not email:
            raise ValidationError("A email is required to login")

        user = User.objects.filter(
            Q(email=email)
            ).distinct()
        if user.exists() and user.count() == 1:
            user_obj = user.first()
        else:
           raise ValidationError("this email is not valid.")
        if user_obj:
             if not user_obj.check_password(password):
                raise ValidationError("Incorrect credentials please try again later.")
        data["token"] = "SOME RANDOM TOKEN"                     
        return data    