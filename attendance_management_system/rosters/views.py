from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.permissions import IsAuthenticated
import users.utils as ui_utils
from datetime import datetime, time

# Create your views here.
# from django.conf import settings

from attendance_management_system import settings

mongo = settings.client


class AddShifts(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    def post(self, request):
        if request.user.role=="manager":
            data = request.data
            for i in data:
                context = {}
                context["date"] = str(i.get("date"))
                context["shift_start_time"] = datetime.strptime(i.get("shift_start_time"), "%H:%M:%S").strftime("%H:%M:%S")
                context["shift_end_time"] = datetime.strptime(i.get("shift_end_time"), "%H:%M:%S").strftime("%H:%M:%S")
                context["assigned_by"] = str(request.user.username)
                context["weekoff"] = str(i.get("weekoff"))
                context["username"] = str(i.get("username"))

                mongo.shifts.update_one({"date": context["date"],"username":context["username"]},
                                                    {"$set": context},upsert=True)
            return ui_utils.handle_response({}, data=data, success=True)
        else:
            return ui_utils.handle_response({}, data="permission denied", success=False)
        
    def get(self, request):
        if request.user.role=="manager":
            data = list(mongo.shifts.find({},{"_id": 0}))
            return ui_utils.handle_response({}, data=data, success=True)
        else:
            return ui_utils.handle_response({}, data="permission denied", success=False)



class StaffDetails(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    def put(self, request):
        if request.user.role == "manager":
            data = request.data

            mongo.base_user.update_one({"username": data["username"]},{"$set": data}, upsert=True)
            return ui_utils.handle_response({}, data=data, success=True)
        else:
            return ui_utils.handle_response({}, data="permission denied", success=False)
        
    def get(self, request):
        if request.user.role == "manager":
            data = list(mongo.base_user.find({"role":"staff"},{"_id":0}))
            return ui_utils.handle_response({}, data=data, success=True)
        else:
            return ui_utils.handle_response({}, data="permission denied", success=False)




class ViewShifts(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    def get(self, request):
        data = list(mongo.shifts.find({"username": request.user.username},{"_id":0}))
        return ui_utils.handle_response({}, data=data, success=True)
        
    def put(self, request):
        # interchange("shift")\
        try:
            context = request.data
            date = context["date"]
            intercgange_by = request.user.username
            interchange_with = context["interchange_username"]
            get_user1_shift = mongo.shifts.find_one({"date": context["date"],"username":intercgange_by},{"_id":0})
            get_user2_shift = mongo.shifts.find_one({"date": context["date"],"username":interchange_with},{"_id":0})

            mongo.shifts.update_one({"date": context["date"],"username":intercgange_by},get_user2_shift)
            mongo.shifts.update_one({"date": context["date"],"username":interchange_with},get_user1_shift)

            return ui_utils.handle_response({}, data="updated", success=True)
        except Exception as e:
            return ui_utils.handle_response({}, data="some error occured", success=False)


class MarkAttendance(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        # interchange("shift")\
        try:
            data = request.data
        
            mongo.attandance_record.insert_one(data)
            find_shift = mongo.shifts.update_one({"date":data["date"], "username": request.user.username},
                                                            {"$set": {"attandance_marked": 1}})
            return ui_utils.handle_response({}, data="updated", success=True)
        except Exception as e:
            return ui_utils.handle_response({}, data="some error occured", success=False)

   