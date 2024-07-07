from rest_framework.response import Response
from django.core.exceptions import PermissionDenied
from rest_framework import status


def handle_response(object_name, data=None, headers=None, content_type=None, exception_object=None, success=False, request=None):
    """
    Args:
        success: determines whether to send success or failure messages
        object_name: The function or class where the error occurs
        data: The user error which you want to display to user's on screens
        exception_object: The exception object caught. an instance of Exception, KeyError etc.
        headers: the dict of headers
        content_type: The content_type.
        request: The request param

        This method can later be used to log the errors.

    Returns: Response object

    """
    if not success:
        # prepare the object to be sent in error response
        data = {
            'general_error': data,
            'system_error': get_system_error(exception_object),
            'culprit_module': object_name,
        }
        if request:
            # fill the data with more information about request
            data['request_data'] = request.data
            data['request_url'] = request.build_absolute_uri()
            data['request_method'] = request.META.get('REQUEST_METHOD')
            data['django_settings_module'] = request.META.get('DJANGO_SETTINGS_MODULE')
            data['http_origin'] = request.META.get('HTTP_ORIGIN')
            data['virtual_env'] = request.META.get('VIRTUAL_ENV')
            data['server_port'] = request.META.get('SERVER_PORT')
            data['user'] = request.user.username if request.user else None

        if isinstance(exception_object, PermissionDenied):
            return Response({'status': False, 'data': data}, headers=headers, content_type=content_type, status=status.HTTP_403_FORBIDDEN)
        else:
            return Response({'status': False, 'data': data}, headers=headers, content_type=content_type, status=status.HTTP_400_BAD_REQUEST)
    else:
        return Response({'status': True, 'data': data}, headers=headers, content_type=content_type,  status=status.HTTP_200_OK)




def get_system_error(exception_object):
    """
    Takes an exception object and returns system error.
    Args:
        exception_object:

    Returns: system error

    """
    if not exception_object:
        return []
    return str(exception_object.args) if exception_object.args else str(
        exception_object) if exception_object else ""
