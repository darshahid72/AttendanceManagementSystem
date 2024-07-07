from rest_framework.serializers import ModelSerializer
from .models import (BaseUser)
from rest_framework import serializers

class BaseUserSerializer(ModelSerializer):
	
	class Meta:
		model = BaseUser
		fields = '__all__'
		


class BaseUserUpdateSerializer(ModelSerializer):
    """
    specific to updating the USER model
    """
    def update(self, instance, validated_data):
        """
        Args:
            instance: The instance to be updated
            validated_data: a dict having data to be updated
        Returns: an updated instance
        """
        # if password provided, then update the password
        password = validated_data.get('password')
        if password:
            instance.set_password(password)
            del validated_data['password']

        for key, value in validated_data.items():
            setattr(instance, key, value)

        instance.save()
        # return the updated instance
        return instance

    class Meta:
        model = BaseUser
        fields = (
            'id', 'first_name', 'last_name', 'email', 'user_code', 'mobile', 
            'password', 'is_superuser','role',
            'designation'
                )
class BaseUserCreateSerializer(ModelSerializer):
    """
    specifically for creating  User objects. There was a need for creating this as standard serializer
    was also containing a nested serializer. It's not possible to write to a serializer if it's nested
    as of Django 1.8.
    """

    def create(self, validated_data):
        """
        Args:
            validated_data: the data that is used to be create the user.

        Returns: sets the password of the user when it's created.
        """

        # get the password
        password = validated_data['password']
        # delete it from the validated_data because we do not want to save it as raw password
        del validated_data['password']
        user = self.Meta.model.objects.create(**validated_data)
        # save password this way
        user.set_password(password)
        # save profile
        user.save()
        # return
        return user

    class Meta:
        model = BaseUser
        fields = (
            'id', 'first_name', 'last_name', 'email', 'user_code', 'username', 'mobile',
            'password','role',
            'designation'
                )
        extra_kwargs = {
            'password': {'write_only': True}
        }



