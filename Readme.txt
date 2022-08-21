/* {% extends 'base.html' %} */


INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',

    'milkapi.apps.MilkapiConfig',
    'rest_framework_simplejwt',
    'knox',
    'rest_framework',
]
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework.authentication.BasicAuthentication',
        'rest_framework.authentication.SessionAuthentication',
        'rest_framework_simplejwt.authentication.JWTAuthentication',
        'knox.auth.TokenAuthentication',
    )
}
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME':'milkapi',
        'USER':'postgres',
        'PORT':'5432',
        'HOST':'127.0.0.1',
        'PASSWORD':'36841327',
    }
}
AUTH_USER_MODEL = 'milkapi.user'

#models
from django.db import models
from django.contrib.auth.models import (
    BaseUserManager, AbstractBaseUser
)

# Create your models here.

class user(AbstractBaseUser):
    RANK=(
        ('Farm_owner','Farm_owner'),
        ('Manager','Manager'),
        ('farm_vertinary_officers','farm_vertinary_officers'),
    
        
    )
    user_id=models.BigAutoField(db_column='user_id',primary_key=True,auto_created=True,
            serialize=False,verbose_name='Id')
    user_name=models.CharField(max_length=255,db_column='user_name',verbose_name='User Name',unique=True)
    user_password=models.CharField('Password',max_length=128,db_column='user_password')
    user_rank=models.CharField(db_column='user_rank',default='Farm_owner',choices=RANK,max_length=25)
    user_last_login=models.DateTimeField(('User Last login'),db_column='user_last_login',blank=True,null=True)
    is_active = models.BooleanField('Account Active',db_column='user_is_active',default=True)
    is_staff = models.BooleanField('Is staff',db_column='user_is_staff',default=False) # a admin user; non super-user
    # notice the absence of a "Password field", that is built in.

    USERNAME_FIELD = 'user_name'
    #REQUIRED_FIELDS = [] # Email & Password are required by default.
    objects= BaseUserManager()
    class Meta:
        db_table='user'
        ordering=('user_name',)
    def __str__(self):
        return f'{self.user_name} {self.user_rank}'

    def get_full_name(self):
        # The user is identified by their email address
        return self.email

    def get_short_name(self):
        # The user is identified by their email address
        return self.email

    def has_perm(self, perm, obj=None):
        "Does the user have a specific permission?"
        # Simplest possible answer: Yes, always
        return True

    def has_module_perms(self, app_label):
        "Does the user have permissions to view the app `app_label`?"
        # Simplest possible answer: Yes, always
        return True

    @property
    def is_staff(self):
        "Is the user a member of staff?"
        return self.staff

class farm_owner(models.Model):
    owner_id=models.AutoField('Owner Id',db_column='owner_id',primary_key=True)
    owner_name=models.CharField('Owner Name',db_column='owner_name',max_length=200)
    owner_phone_number=models.CharField('Phone Number',unique=True,max_length=10,db_column='owner_phone_number')
    owner_email=models.EmailField('Owner Email',db_column='owner_email',unique=True)
    owner_user_id=models.ForeignKey(user,db_column='owner_user_id',on_delete=models.CASCADE)

    class Meta:
        db_table='farm_owner'
        ordering=('owner_name',)
    def __str__(self):
        return f'{self.owner_name} {self.owner_phone_number}'

class manager(models.Model):
    manager_id=models.AutoField('Manager Id',primary_key=True,db_column='manager_id')
    manager_name=models.CharField('Manager Name',db_column='manager_name',max_length=255)
    manager_phone_number=models.CharField('Phone Number',unique=True,db_column='manager_phone_number',max_length=10)
    manager_user_id=models.ForeignKey(user,db_column='manager_user_id',on_delete=models.CASCADE,verbose_name='Manger_user Id')
    class Meta:
        db_table='manager'
        ordering=('manager_name',)
    def __str__(self):
        return f"{self.manager_name} {self.manager_phone_number}"
class farm_vertinary_officer(models.Model):
    vet_id=models.AutoField('Vet Id',primary_key=True,db_column='vet-id')
    vet_name=models.CharField('Vet Name',max_length=255,db_column='vet_name')
    vet_phone_number=models.CharField('Vet Phonenumber',unique=True,max_length=10,db_column='vet_phone_number')
    vet_email=models.EmailField('Vet Email',db_column='vet_email',unique=True)
    vet_user_id=models.ForeignKey(user,db_column='vet_user_id',on_delete=models.CASCADE,verbose_name='Vet_user Id')
    class Meta:
        db_table='farm_vertinary_officer'
        ordering=('vet_name',)
    def __str__(self):
        return f'{self.vet_name} {self.vet_email} {self.vet_phone_number}'
class animal_types(models.Model):
    choice=(
        ('Fres-1','Fres-1'),
        ('Gars-2','Gars-2'),
        ('Jers-3','Jers-3'),

    )
    animal_id=models.AutoField('Animal Id',primary_key=True,db_column='animal_id')
    animal_ref=models.CharField('Animal Ref',db_column='animal_ref',max_length=255,unique=True)
    animal_name=models.CharField('Animal Name',db_column='animal_name',max_length=100)
    animal_type_id=models.CharField('Animal_type Id',max_length=25,db_column='animal_type_id',choices=choice)
    class Meta:
        db_table='animal_types'
        ordering=('animal_type_id',)
    def __str__(self):
        return f'{self.animal_name} - {self.animal_type_id}'
class milk_production(models.Model):
    production_id=models.AutoField('Production Id',db_column='production_id',primary_key=True)
    production_animal_id=models.ForeignKey(animal_types,db_column='production_animal_id',
    verbose_name='Production_animal Id',on_delete=models.CASCADE)
    production_morning_quantity=models.FloatField(
        'Morning Quantity(litres)',db_column='production_morning_quantity' 
    )
    production_evening_quantity=models.FloatField(
        'Evening Quantity(litres)',db_column='production_evening_quantity' 
    )
    production_date=models.DateTimeField('Production Date',auto_now_add=True,db_column='Production_date')
    production_total_quantity=models.FloatField('Total Production(litres)',blank=True,db_column='production_total_quantity')
    class Meta:
        db_table='milk_production'
        ordering=('production_date',)
    def save(self,*args,**kwargs):
        self.production_total_quantity=self.production_morning_quantity + self.production_evening_quantity
        super().save(*args,**kwargs)
    def __str__(self):
        return f'{self.production_id}-{self.production_date} -total_milk- {self.production_total_quantity}'.format(self.production_id,
        self.production_date,self.production_total_quantity)
class suppliment (models.Model):
    suppliment_id=models.AutoField('Suppliment Id',db_column='suppliment_id',primary_key=True)
    suppliment_animal_id=models.ForeignKey(animal_types,db_column='suppliment_animal_id',
    verbose_name='Suppliment_animal Id',on_delete=models.CASCADE)
    suppliment_date=models.DateTimeField('Suppliment Date',db_column='suppliment_date',auto_now_add=True)
    suppliment_desc=models.TextField('Suppliment Desc',db_column='suppliment_desc')
    class Meta:
        db_table='suppliment'
        ordering=('suppliment_id',)
    def __str__(self):
        return f'{self.suppliment_id}-{self.suppliment_date}'
class vet_visists (models.Model):
    vet_visit_id=models.AutoField('Visit Id',db_column='vet_visit_id',primary_key=True)
    vet_animal_id=models.ForeignKey(animal_types,db_column='vet_animal_id',
    verbose_name='Vet_animal Id',on_delete=models.CASCADE)
    vet_visist_date=models.DateTimeField('Visist Date',db_column='vet_visist_date',auto_now_add=True)
    vet_visist_desc=models.TextField('Visist Desc',db_column='vet_visist_desc')
    class Meta:
        db_table='vet_visists '
        ordering=('vet_visist_date',)
    def __str__(self):
        return f'{self.vet_visit_id}-{self.vet_visist_date}'
class vet_visist_prescription (models.Model):
    prescription_id=models.AutoField('Prescription Id',db_column='prescription_id',primary_key=True)
    prescription_vet_visist_id=models.ForeignKey(vet_visists,db_column='prescription_vet_visist_id',
    verbose_name='Prescription_vet_visistId',on_delete=models.CASCADE)
    prescription_description=models.TextField('Prescription Desc',db_column='prescription_description')
    class Meta:
        db_table='vet_visist_prescription'
        ordering=('prescription_id',)
    def __str__(self):
        return f'{self.prescription_id}-{self.prescription_vet_visist_id}'
class AI_services(models.Model):
    AI_service_id=models.AutoField('Service Id',db_column='AI_service_id',primary_key=True)
    AI_animal_id=models.ForeignKey(animal_types,verbose_name='AI_animal Id',
    db_column='AI_animal_id=',on_delete=models.CASCADE)
    AI_vet_id=models.ForeignKey(vet_visists,verbose_name='AI_vet Id',db_column='AI_vet_id',
    on_delete=models.CASCADE)
    AI_comments=models.TextField('AI comments',db_column='AI_comments')
    class Meta:
        db_table='AI_services'
        ordering=('AI_service_id',)
    def __str__(self):
        return f'{self.AI_service_id}-{self.AI_vet_id}'

#serializers
from rest_framework.serializers import ModelSerializer
from .models import animal_types
from rest_framework import generics, permissions
from rest_framework import serializers
from django.contrib.auth.models import User

# User Serializer
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id','email', 'username')

# Register Serializer
class RegisterSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'username','email','password')
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        user = User.objects.create_user(validated_data['username'],validated_data['email'] ,validated_data['password'])

        return user
class ChangePasswordSerializer(serializers.Serializer):
    model = User

    """
    Serializer for password change endpoint.
    """
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)
#models searializers
class animal_types_serializer(ModelSerializer):
    class Meta:
        model=animal_types
        fields='__all__'

#views
from django.shortcuts import render
from django.contrib.auth import login
from .models import animal_types
from rest_framework import generics, permissions,status
from rest_framework.response import Response
from django.contrib.auth.models import User
from knox.models import AuthToken
from rest_framework.permissions import IsAuthenticated  
from rest_framework.authtoken.serializers import AuthTokenSerializer
from knox.views import LoginView as KnoxLoginView
from .serializers import UserSerializer, RegisterSerializer,ChangePasswordSerializer,animal_types_serializer
from django.views.decorators.debug import sensitive_post_parameters

# Register API
class RegisterAPI(generics.GenericAPIView):
    serializer_class = RegisterSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        return Response({
        "user": UserSerializer(user, context=self.get_serializer_context()).data,
        "token": AuthToken.objects.create(user)[1]
        })
class LoginAPI(KnoxLoginView):
    permission_classes = (permissions.AllowAny,)

    def post(self, request, format=None):
        serializer = AuthTokenSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        login(request, user)
        return super(LoginAPI, self).post(request, format=None)

class UserAPI(generics.RetrieveAPIView):
    permission_classes = [permissions.IsAuthenticated,]
    #IsAuthenticated,
    serializer_class = UserSerializer

    def get_object(self):
        return self.request.user

# Change Password 

class ChangePasswordView(generics.UpdateAPIView):
    """
    An endpoint for changing password.
    """
    serializer_class = ChangePasswordSerializer
    model = User
    permission_classes = (IsAuthenticated,)

    def get_object(self, queryset=None):
        obj = self.request.user
        return obj

    def update(self, request, *args, **kwargs):
        self.object = self.get_object()
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            # Check old password
            if not self.object.check_password(serializer.data.get("old_password")):
                return Response({"old_password": ["Wrong password."]}, status=status.HTTP_400_BAD_REQUEST)
            # set_password also hashes the password that the user will get
            self.object.set_password(serializer.data.get("new_password"))
            self.object.save()
            response = {
                'status': 'success',
                'code': status.HTTP_200_OK,
                'message': 'Password updated successfully',
                'data': []
            }

            return Response(response)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

#Get json data from anaimal_type model using geberic APIView
class animal_type_List(generics.ListCreateAPIView):
    queryset=animal_types.objects.all()
    serializer_class=animal_types_serializer
class animal_type_details(generics.RetrieveUpdateDestroyAPIView):
    queryset=animal_types.objects.all()
    serializer_class=animal_types_serializer

#urls app
from django.urls import path
from knox import views as knox_views
from . import views

urlpatterns=[
    #Register user
    path('register/', views.RegisterAPI.as_view(), name='register'),

    #login logout urls
    path('login/', views.LoginAPI.as_view(), name='login'),
    path('logout/', knox_views.LogoutView.as_view(), name='logout'),
    path('logoutall/',knox_views.LogoutAllView.as_view(), name='logoutall'),

    #Authentication urls
    path('user/', views.UserAPI.as_view(), name='user'),
    path('change-password/', views.ChangePasswordView.as_view(), name='change-password'),

    #Models apis urls
    path('animal-list/',views.animal_type_List.as_view(),name='animal-types-list'),
    path('animal-type-details/<str:pk>/',views.animal_type_details.as_view(),name='animal-type-details')

]

#urls main proj
"""milk_manager URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path,include


urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/',include('milkapi.urls'))
]


#admin
from django.contrib import admin
from .models import user,farm_owner,manager,animal_types,milk_production,suppliment,vet_visists,vet_visist_prescription,AI_services,farm_vertinary_officer

# Register your models here.
admin.site.register(user)
admin.site.register(farm_owner)
admin.site.register(manager)
admin.site.register(farm_vertinary_officer)
admin.site.register(animal_types)
admin.site.register(milk_production)
admin.site.register(suppliment)
admin.site.register(vet_visists)
admin.site.register(vet_visist_prescription)
admin.site.register(AI_services)

