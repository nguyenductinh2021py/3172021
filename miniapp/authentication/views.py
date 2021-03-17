from django.shortcuts import render
from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken, OutstandingToken
from authentication.serializers import RegisterSerializer, LoginSerializer, AccessToken, ChangePasswordSerializer
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework import status
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout



from rest_framework.response import Response
class RegisterView(APIView):
    permission_classes = (IsAuthenticated,)
    
    def post(self, request):
        access = request.data['access']
        if AccessToken(access).check_blacklist():
            return Response({"Token": "The token in blacklisted", "status_code": status.HTTP_403_FORBIDDEN}, status=status.HTTP_403_FORBIDDEN)
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            response = {
                "username": serializer.data['username'],
                "status_code": status.HTTP_201_CREATED
            }
            return Response(response, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class LoginView(APIView):
    permission_classes = (AllowAny, )

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
      
        login(request, user)
        access = AccessToken.for_user(user)
        response = {
            "id": user.id,
            "username": user.username,
            "status.code": status.HTTP_200_OK,
            "token": str(access)
        }
        return Response(response, status=status.HTTP_200_OK)

class LogoutView(APIView):
    permission_classes = (AllowAny, )
    def post(self, request):
        tokens = OutstandingToken.objects.filter(user_id=request.user.id)
        for token in tokens:
            BlacklistedToken.objects.get_or_create(token=token)
        logout(request)
        return Response(status=status.HTTP_204_NO_CONTENT)

class CheckToken(APIView):
    def get(self, request):
        access = request.data['access']
        if AccessToken(access).check_blacklist():
            return Response({"Token": "The token in blacklisted", "status_code": status.HTTP_403_FORBIDDEN}, status=status.HTTP_403_FORBIDDEN)
        return Response({"Token": access, "status_code": status.HTTP_200_OK}, status=status.HTTP_200_OK)
class ChangePasswordView(APIView):
    permission_classes = (IsAuthenticated, )
    
    def put(self, request):
        serializer = ChangePasswordSerializer(data=request.data)
        if serializer.is_valid():
            username = request.data['username']
            password = request.data['password']
            user = User.objects.get(username=username)
            user.set_password(password)
            user.save()
            response = {
                "username": username,
                "status_code": status.HTTP_200_OK
            }
            return Response(response, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_200_OK)