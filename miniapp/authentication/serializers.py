from rest_framework import serializers
from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from rest_framework_simplejwt.token_blacklist.models import OutstandingToken
from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken
from rest_framework_simplejwt.tokens import  BlacklistMixin, Token
from rest_framework_simplejwt.settings import api_settings

class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(max_length=255, min_length=6, write_only=True)
    password2 = serializers.CharField(max_length=255, min_length=6, write_only=True)
    email = serializers.EmailField(max_length=255, min_length=6)
    class Meta:
        model = User
        fields = ['username', 'password', 'password2', 'email', 'is_staff']
    
    def create(self, validate_data):
        username = validate_data['username']
        password = validate_data['password']
        password2 = validate_data['password2']
        email = validate_data['email']
        is_staff = validate_data['is_staff']
        if User.objects.filter(username=username):
            raise serializers.ValidationError({"username": "The username is already in use"})
        if User.objects.filter(email=email):
            raise serializers.ValidationError({"email": "The email is already in use"})
        if password != password2:
            raise serializers.ValidationError({"password": "Two password not match"})
        
        user = User(username=username, email=email, is_staff=is_staff)
        user.set_password(password)
        user.save()
        return user

class LoginSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=255, min_length=4)
    password = serializers.CharField(max_length=64, min_length=6)
    class Meta:
        model=User
        fields=['username', 'password']

    def validate(self, validate_data):
        username=validate_data.get("username", None)
        password=validate_data.get("password", None)

        if not User.objects.filter(username=username) and not User.objects.filter(email=username):
            raise serializers.ValidationError({"username":"username does not exist"})
       
        try:
            user = authenticate(username=User.objects.get(email=username), password=password)
        except:
            user = authenticate(username=username, password=password)
        
        if user is None:
            raise serializers.ValidationError({"password":"password does not exists"})
        validate_data['user']=user
        return validate_data

class BlacklistMixin(BlacklistMixin):
    def check_blacklist(self):
        jti = self.payload[api_settings.JTI_CLAIM]
        if BlacklistedToken.objects.filter(token__jti=jti).exists():
            return True
        return False

# save access token in Outstanding
class AccessToken(BlacklistMixin, Token):
    token_type = 'access'
    lifetime = api_settings.ACCESS_TOKEN_LIFETIME
    no_copy_claims = (
        api_settings.TOKEN_TYPE_CLAIM,
        'exp',
        api_settings.JTI_CLAIM,
        'jti',
    ) 

class ChangePasswordSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=64, min_length=3)
    password = serializers.CharField(max_length=64, min_length=6, write_only=True)
    confirm_password = serializers.CharField(max_length=64, min_length=6, write_only=True)
    password_old = serializers.CharField(max_length=64, min_length=6, write_only=True)

    def validate(self, validated_data):
        username = validated_data['username']
        password = validated_data['password']
        confirm_password = validated_data['confirm_password']
        password_old = validated_data['password_old']

        if password != confirm_password:
            raise serializers.ValidationError({"confirm_password":"Confirm password was not match"})
        if password == password_old:
            raise serializers.ValidationError({"pasword": "The same password"})
        user = authenticate(username=username, password=password_old)
        if user is None:
            raise serializers.ValidationError({"password_old":"The old password is not correct"})
        return validated_data

class ChangeProfileSerializer(serializers.ModelSerializer):
    username = serializers.CharField(max_length=64, min_length=6)
    email = serializers.CharField(max_length=255, min_length=12)

    class Meta:
        model = User
        fields = ['username', 'email', 'first_name', 'last_name', 'address', 'avatar']

    def update(self, instance, validate_data):
        username = validate_data.get('username', None)
        email = validate_data.get('email', None)
        user = User.objects.get(email=email)
        if user and str(user.username) != username:
            raise serializers.ValidationError({"email": "The email already exists"})
        instance.last_name = validate_data.get('last_name', instance.last_name)
        instance.first_name = validate_data.get('first_name', instance.first_name)
        instance.email = validate_data.get('email', instance.email)
        instance.address = validate_data.get('address', instance.address)
        instance.avatar = validate_data.get('avatar', instance.avatar)
        instance.save()
        return instance