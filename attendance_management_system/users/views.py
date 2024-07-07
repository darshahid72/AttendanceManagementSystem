from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth import authenticate
from django.contrib.auth.models import update_last_login
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.token_blacklist.models import OutstandingToken




import json
import random
import re
from django.db.models import Q

from django.apps import apps
from django.conf import settings
from django.contrib.auth.models import Group, Permission
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import ObjectDoesNotExist
from django.forms import model_to_dict
from rest_framework import permissions, status, viewsets
# from v0.ui.inventory.serializers import SupplierTypeSocietySerializer
from rest_framework.decorators import action
import users.utils as ui_utils
from .models import BaseUser
from rest_framework.views import APIView
from attendance_management_system import settings

mongo = settings.client

 
from .serializer import (BaseUserCreateSerializer,
                                    BaseUserSerializer,
                                    BaseUserUpdateSerializer)


# Create your views here.
class UserViewSet(APIView):
    """
    A View set for handling all the user related logic
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request, pk=None):
        """
        The API is only used to fetch one User object by user id.
        Args:
            request: The request body
            pk: The pk of BaseUser table

        Returns: a User object
        """
        print(request.user.id)
        class_name = self.__class__.__name__
        try:
            user = BaseUser.objects.get(id=request.user.id)
            serializer = BaseUserSerializer(user)
            return ui_utils.handle_response(class_name, data=serializer.data, success=True)
        except ObjectDoesNotExist as e:
            return ui_utils.handle_response(class_name, data=pk, exception_object=e)
        except Exception as e:
            return ui_utils.handle_response(class_name, exception_object=e, request=request)

    def put(self, request, pk=None):
        """
        API used to update one single user. The API does not update a password for a user, though you have to
        provide password in the request body. There is a separate api for updating password of the user.
        Args:
            request: A request body
            pk: pk value

        Returns: updated one object

        """
        class_name = self.__class__.__name__
        try:
            user = BaseUser.objects.get(username=request.data.get("username"))
            serializer = BaseUserUpdateSerializer(user, data=request.data)
            if serializer.is_valid():
                user = serializer.save()
                return ui_utils.handle_response(class_name, data=serializer.data, success=True)
            return ui_utils.handle_response(class_name, data=serializer.errors)
        except ObjectDoesNotExist as e:
            return ui_utils.handle_response(class_name, data=pk, exception_object=e)
        except Exception as e:
            return ui_utils.handle_response(class_name, exception_object=e, request=request)

    def post(self, request):
        """
        Create one single user
        Args:
            request:  Request body

        Returns: created user
        """
        class_name = self.__class__.__name__
        
        data = request.data
        password = data['password']
        serializer = BaseUserCreateSerializer(data=data)
        if validate_password(password) == 0:
            return ui_utils.handle_response(class_name,
                                            data='password should have 8 chars including a capital'
                                            'and a special char', success=False)
        if serializer.is_valid():
            serializer.save()
            return ui_utils.handle_response(class_name, data=serializer.data, success=True)
        return ui_utils.handle_response(class_name, data=serializer.errors)
        # except Exception as e:
        #     return ui_utils.handle_response(class_name, exception_object=e, request=request)

    def list(self, request):
        """
        list all users in the system
        Args:
            request: The request body

        Returns: list all users

        """
        class_name = self.__class__.__name__
        try:
            next_page = request.query_params.get("next_page")
            search = request.query_params.get("search") or  ''
            if request.user.is_superuser:
                if search:
                    users = BaseUser.objects.filter(Q(email__icontains = search) | Q(username__icontains = search) | Q(profile__organisation__name__icontains = search) | Q(first_name__icontains = search) | Q(last_name__icontains = search),profile__organisation=organisation_id)
                else:
                    users = BaseUser.objects.all()
            else:
                organisation_id = request.query_params.get('organisation_id',None)
                users = []
                if organisation_id:
                    if search:
                        users = BaseUser.objects.filter(Q(email__icontains = search) | Q(username__icontains = search) | Q(profile__organisation__name__icontains = search) | Q(first_name__icontains = search) | Q(last_name__icontains = search),profile__organisation=organisation_id)
                    else:
                        users = BaseUser.objects.filter(profile__organisation=organisation_id)
            
            serializer = BaseUserSerializer(users, many=True)
            if next_page:
                pagination = paginate(users,BaseUserSerializer,request,next_page,limit = 20)
                return ui_utils.handle_response(class_name, pagination, success=True)
            return ui_utils.handle_response(class_name, data = serializer.data, success=True)
        except Exception as e:
            return ui_utils.handle_response(class_name, exception_object=e, request=request)

    def destroy(self, request, pk=None):
        """
        Deletes a single user
        Args:
            request: The Request body
            pk: pk value

        Returns: pk of object which got deleted

        """
        class_name = self.__class__.__name__
        try:
            BaseUser.objects.get(pk=pk).delete()
            return ui_utils.handle_response(class_name, data=pk, success=True)
        except ObjectDoesNotExist as e:
            return ui_utils.handle_response(class_name, data=pk, exception_object=e)
        except Exception as e:
            return ui_utils.handle_response(class_name, exception_object=e, request=request)

    @action(detail=True, methods=['post'])
    def change_password(self, request, pk=None):
        """
        This API must be used only to change password of the user.
        Args:
            request: Request method
            pk: pk value
        Returns: changes the password of the BaseUser instance and returns a success message

        """
        class_name = self.__class__.__name__
        try:
            user = BaseUser.objects.get(pk=pk)
            new_password = request.data['password']
            password_valid = validate_password(new_password)
            # if not user.is_superuser:
            # old_input_password = request.data['old_password']
            # if not user.check_password('{}'.format(old_input_password)):
            #     return ui_utils.handle_response(class_name, data='Your Old Password is wrong', success=False)
            if password_valid == 1:
                user.set_password(new_password)
                user.save()
                return ui_utils.handle_response(class_name, data='Password changed successfully', success=True)
            else:
                return ui_utils.handle_response(
                    class_name,
                    data='Please make sure to have at least 1 capital letter, 1 small \
                        letter, 1 special character and minimum 8 characters.', success=False)
        except ObjectDoesNotExist as e:
            return ui_utils.handle_response(class_name, data=pk, exception_object=e)
        except Exception as e:
            return ui_utils.handle_response(class_name, exception_object=e, request=request)


def validate_password(new_password):
    # used to check whether the new password is strong enough
    valid = 1
    # if not any(x.isupper() for x in new_password):
    #     valid = 0
    # if re.match("[^a-zA-Z0-9_]", new_password):
    #     valid = 0
    if len(new_password) < 8:
        valid = 0
    elif not re.search("[a-z]", new_password):  # Password should have lowercase letters.
        valid = 0
    elif not re.search("[A-Z]", new_password):  # Password should have uppercase letters.
        valid = 0
    elif not re.search("[0-9]", new_password):  # Password should have numbers.
        valid = 0
    elif not re.search("[_@$#%&*]", new_password):  # Password should have special characters like _ @ $ # % & *
        valid = 0
    elif re.search("\s", new_password):  # Password should not contain spaces.
        valid = 0
    return valid




class LoginView(APIView):
    permission_classes = []

    def post(self, request, *args, **kwargs):
        username = request.data.get('username')
        password = request.data.get('password')

        # Debug: Print incoming username and password
        print(f"Username: {username}, Password: {password}")

        # Retrieve user object based on username
        user = BaseUser.objects.filter(username=username).first()

        # Debug: Print user object
        print(f"User object: {user}")

        if user is not None:
            # Authenticate user with provided password
            authenticated_user = authenticate(username=username, password=password)
            
            # Debug: Print authenticated user
            print(f"Authenticated User: {authenticated_user}")

            if authenticated_user is not None:
                try:
                    # Handle existing tokens (optional step, if you want to invalidate them)
                    OutstandingToken.objects.filter().delete()

                    # If authentication is successful, generate tokens
                    refresh = RefreshToken.for_user(authenticated_user)
                    update_last_login(None, authenticated_user)
                    
                    # Debug: Print refresh token
                    print(f"Refresh Token: {refresh}")

                    return Response({
                        'refresh': str(refresh),
                        'access': str(refresh.access_token),
                    }, status=status.HTTP_200_OK)
                except TokenError as e:
                    # Debug: Print exception details
                    print(f"Token Generation Error: {e}")
                    return Response({'detail': 'Token generation failed'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                except Exception as e:
                    # Debug: Print exception details
                    print(f"General Error: {e}")
                    return Response({'detail': 'An error occurred'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            else:
                return Response({'detail': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)
        else:
            return Response({'detail': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
