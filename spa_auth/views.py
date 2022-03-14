import datetime
import random
import string

import pyotp
from django.shortcuts import render
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import exceptions

from spa_auth.authorization import create_access_token, create_refresh_token, JWTAuthentication, decode_refresh_token
from spa_auth.models import User, UserToken, Reset
from spa_auth.serializers import UserSerializer


def index(request):
    return render(request, template_name='index.html')


class RegisterAPIView(APIView):
    def post(self, request):
        data = request.data
        if data['password'] != data['password_confirm']:
            raise exceptions.APIException('Password don\'t match')

        serializer = UserSerializer(data=data)
        serializer.is_valid(raise_exception=True)
        print(123)
        serializer.save()
        print(serializer.data)
        return Response(serializer.data)


class LoginAPIView(APIView):
    """ there will be cors error if not install django-cors-headers
        add it to installed apps as corsheaders and to middleware as corsheaders.middleware.CorsMiddleware
    """

    def post(self, request):
        email = request.data['email']
        password = request.data['password']
        user = User.objects.filter(email=email).first()
        user_id = user.id
        if user is None:
            raise exceptions.AuthenticationFailed('invalid credentials')

        if not user.check_password(password):
            raise exceptions.AuthenticationFailed('invalid credentials')

        if user.two_factor_auth_secret:
            return Response({
                'id': user_id
            })

        secret = pyotp.random_base32()
        opt_auth_url = pyotp.totp.TOTP(secret).provisioning_uri(issuer_name='My App')

        return Response({
            "id": user_id,
            "secret": secret,
            "opt_auth_url": opt_auth_url
        })


class UserAPIView(APIView):
    authentication_classes = [JWTAuthentication]  # it's a middleware

    def get(self, request):
        return Response(UserSerializer(request.user).data)


class TwoFactorLoginApiView(APIView):
    def post(self, request):
        user_id = request.data['id']
        user = User.objects.filter(pk=user_id).first()
        if not user:
            raise exceptions.AuthenticationFailed('invalid credentials')

        secret = user.two_factor_auth_secret if user.two_factor_auth_secret is "" else request.data['secret']
        totp = pyotp.TOTP(secret)
        if not totp.verify(request.data['code']):
            raise exceptions.AuthenticationFailed('invalid credentials')

        if user.two_factor_auth_secret == '':
            user.two_factor_auth_secret = secret
            user.save()

        access_token = create_access_token(user_id)
        refresh_token = create_refresh_token(user_id)

        UserToken.objects.create(user_id=user_id, token=refresh_token,
                                 expired_at=datetime.datetime.utcnow() + datetime.timedelta(days=7))

        if not UserToken.objects.filter(user_id=user_id, token=refresh_token,
                                        expired_at__gt=datetime.datetime.now(tz=datetime.timezone.utc)).exists():
            raise exceptions.AuthenticationFailed('unauthenticated')

        response = Response()
        response.set_cookie(key='refresh_token', value=refresh_token, httponly=True)  # httponly - on back can access
        response.data = {
            "token": access_token
        }
        return response


class RefreshAPIView(APIView):
    def post(self, request):
        refresh_token = request.COOKIES.get('refresh_token')
        user_id = decode_refresh_token(refresh_token)
        access_token = create_access_token(user_id)
        return Response({
            'token': access_token
        })


class LogoutAPIView(APIView):
    def post(self, request):
        refresh_token = request.COOKIES.get('refresh_token')
        UserToken.objects.filter(token=refresh_token)
        response = Response()
        response.delete_cookie('refresh_token')
        response.data = {
            'message': 'success'
        }
        return response


class ForgotAPIView(APIView):
    def post(self, request):
        token = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(10))
        Reset.objects.create(email=request.data.email, token=token)
        # SEND EMAIL WITH LINK TO RESET PASSWORD (reset)
        return Response({
            "message": 'success'
        })


class ResetAPIView(APIView):
    def post(self, request):
        data = request.data
        if data['password'] != data['password_confirm']:
            raise exceptions.APIException('Password don\'t match')

        reset_password = Reset.objects.filter(token=data.token).first()

        if not reset_password:
            raise exceptions.APIException('Invalid link')

        user = User.objects.filter(email=reset_password.email).first()
        if not user:
            raise exceptions.APIException('User was not found')

        user.set_password(data['password'])
        return Response({
            "message": "success"
        })
