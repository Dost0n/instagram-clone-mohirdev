from rest_framework import permissions
from rest_framework.generics import CreateAPIView, UpdateAPIView
from users import serializers
from users.serializers import (SignUpSerializer, ChangeUserInformationSerializer, ChangeUserPhotoSerializer, LoginSerializer,
                               LoginRefreshSerializer, LogoutSerializer, ForgotPassswordSerializer, ResetPasswordSerializer)  
from users.models import CODE_VERIFIED, NEW, VIA_EMAIL, VIA_PHONE, User, DONE, PHOTO_DONE
from rest_framework.views import APIView
from django.utils.datetime_safe import datetime
from rest_framework.exceptions import ValidationError, NotFound
from rest_framework.response import Response
from shared.utility import send_email
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError
from drf_yasg.utils import swagger_auto_schema
from shared.utility import check_email_username_or_phone
from django.core.exceptions import ObjectDoesNotExist

class CreateUserView(CreateAPIView):
    queryset = User.objects.all()
    permission_classes = (permissions.AllowAny, )
    serializer_class = SignUpSerializer


class VerifyAPIView(APIView):
    permission_classes = (permissions.IsAuthenticated, )

    def post(self, request, *args, **kwargs):
        user = self.request.user
        code = self.request.data.get('code')
        self.check_verify(user, code)
        return Response(
                data = {
                    'status':True,
                    'auth_status':user.auth_status,
                    "access": user.token()['access'],
                    "refresh": user.token()['refresh']
                }
            )
    

    @staticmethod
    def check_verify(user, code):
        verifies = user.verify_codes.filter(expiration_time__gte = datetime.now(), code=code, is_isconfirmed=False)
        if not verifies.exists():
            data = {
                "message":"Tasdiqlash kodingiz xato yoki eskirgan"
            }
            raise ValidationError(data)
        verifies.update(is_isconfirmed=True)
        if user.auth_status == NEW:
            user.auth_status = CODE_VERIFIED
            user.save()
            return True
            

class GetNewVerification(APIView):
    permission_classes = (permissions.IsAuthenticated, )

    def get (self, request, *args, **kwargs):
        user = self.request.user
        self.check_verification(user)
        if user.auth_type == VIA_EMAIL:
            code = user.create_verify_code(VIA_EMAIL)
            send_email(user.email, code)
        elif user.auth_type == VIA_PHONE:
            code = user.create_verify_code(VIA_PHONE)
            send_email(user.phone_number, code)
        else:
            data = {
                'message':"Email yoki Phone number xato!"
            }
            raise ValidationError(data)
        return Response(
            {
                'success':True,
                'message':"Tasdiqlash kodingiz qaytadan jo'natildi"
            }
        )
    
    @staticmethod
    def check_verification(user):
        verifies = user.verify_codes.filter(expiration_time__gte = datetime.now(), is_isconfirmed=False)
        if verifies.exists():
            data = {
                'message':"Kodingiz hali ishlatish uchun yaroqli. Biroz kutib turing"
            }
            raise ValidationError(data)
    

class ChangeUserInformationView(UpdateAPIView):
    permission_classes = (permissions.IsAuthenticated, )
    serializer_class = ChangeUserInformationSerializer
    http_method_names = ['patch', 'put']

    def get_object(self):
        return self.request.user
    
    def update(self, request, *args, **kwargs):
        super(ChangeUserInformationView, self).update(request, *args, **kwargs)
        data = {
            'success' : True,
            'message' : "User updated successfully",
            'auth_status':self.request.user.auth_status
        }
        return Response(data, status=200)
    

    def partial_update(self, request, *args, **kwargs):
        super(ChangeUserInformationView, self).partial_update(request, *args, **kwargs)
        data = {
            'success' : True,
            'message' : "User updated successfully",
            'auth_status':self.request.user.auth_status
        }
        return Response(data, status=200)


class ChangeUserPhotoView(APIView):
    permission_classes = (permissions.IsAuthenticated, )

    def put(self, request, *args, **kwargs):
        serializer = ChangeUserPhotoSerializer(data = request.data)
        if serializer.is_valid():
            user = request.user
            serializer.update(user, serializer.validated_data)
            return Response({
                'message':"Rasm muvaffaqiyatli yuklandi!!"
            }, status = 200)
        
        return Response(
            serializer.erorrs, status = 400
        )


class SkipChangePhotoView(APIView):
    permission_classes = (permissions.IsAuthenticated, )

    def post(self, request, *args, **kwargs):
        user = self.request.user
        if user.auth_status == DONE:
            user.auth_status = PHOTO_DONE
            user.save()
            return Response(
            {
                'success':True,
                'message':"Ro'yhatdan o'tish muvaffaqiyatli yakunlandi!"
            })
        else:
            data = {
                'message':"Noto'g'ri buyruq berildi."
            }
            return Response(
            data, status = 400
        )
        

class LoginView(TokenObtainPairView):
    serializer_class = LoginSerializer


class LoginRefreshView(TokenRefreshView):
    serializer_class = LoginRefreshSerializer


class LogoutView(APIView):
    serializer_class = LogoutSerializer
    permission_classes = (permissions.IsAuthenticated,)

    @swagger_auto_schema(request_body=LogoutSerializer)
    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=self.request.data)
        serializer.is_valid(raise_exception=True)
        try:
            refresh_token = self.request.data['refresh']
            token = RefreshToken(refresh_token)
            token.blacklist()
            data = {
                "success":True,
                "message":"You are loggout out"
            }
            return Response(data, status=205)
        except TokenError:
            return Response(status=400)


class ForgotPasswordView(APIView):
    serializer_class = ForgotPassswordSerializer
    permission_classes = (permissions.AllowAny,)

    @swagger_auto_schema(request_body=ForgotPassswordSerializer)
    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data = self.request.data)
        serializer.is_valid(raise_exception=True)
        email_or_phone = serializer.validated_data.get('email_or_phone')
        user = serializer.validated_data.get('user')
        if check_email_username_or_phone(email_or_phone) =='phone':
            print
            code = user.create_verify_code(VIA_PHONE)
            send_email(email_or_phone, code)
        if check_email_username_or_phone(email_or_phone) =='email':
            code = user.create_verify_code(VIA_EMAIL)
            send_email(email_or_phone, code)
        return Response(
            {
                'success': True,
                'message': "Tasdiqlash kodi muvaffaqiyatli yuborildi!!",
                'access': user.token()['access'],
                "refresh": user.token()['refresh'],
                "user_status": user.auth_status
            }, status=200
        )



class ResetPasswordView(UpdateAPIView):
    serializer_class = ResetPasswordSerializer
    permission_classes = (permissions.IsAuthenticated,)
    http_method_name = ['patch', 'put']


    def get_object(self):
        return self.request.user
    
    def update(self, request, *args, **kwargs):
        response = super(ResetPasswordSerializer, self).update(request, *args, **kwargs)
        try:
            user = User.objects.get(id = response.data.get('id'))
        except ObjectDoesNotExist:
            raise NotFound(detail="User not found")
        return Response(
            {
                "success":True,
                "message":"Parolingiz muvaffaqiyatli o'zgartirildi!!!",
                "access":user.token()['access'],
                "access":user.token()['refresh_token'],
            }
        )

# class GetNewVerification(APIView):
#     def get (self, request, *args, **kwargs):
#         user = self.request.user
#         check_code = self.check_verification(user)
#         if check_code:
#             if user.auth_type == VIA_EMAIL:
#                 code = user.verify_codes.get(expiration_time__gte = datetime.now()).code
#                 send_email(user.email, code)
#             elif user.auth_type == VIA_PHONE:
#                 code = code = user.verify_codes.get(expiration_time__gte = datetime.now()).code
#                 send_email(user.phone_number, code)
#             else:
#                 data = {
#                     'message':"Email yoki Phone number xato!"
#                 }
#                 raise ValidationError(data)
#         else:
#             if user.auth_type == VIA_EMAIL:
#                 code = user.create_verify_code(VIA_EMAIL)
#                 send_email(user.email, code)
#             elif user.auth_type == VIA_PHONE:
#                 code = user.create_verify_code(VIA_PHONE)
#                 send_email(user.phone_number, code)
#             else:
#                 data = {
#                     'message':"Email yoki Phone number xato!"
#                 }
#                 raise ValidationError(data)
#         return Response(
#             {
#                 'success':True,
#                 'message':"Tasdiqlash kodingiz qaytadan jo'natildi"
#             }
#         )
    
#     @staticmethod
#     def check_verification(user):
#         verifies = user.verify_codes.filter(expiration_time__gte = datetime.now(), is_isconfirmed=False)
#         if verifies.exists():
#             return True
#         else:
#             return False