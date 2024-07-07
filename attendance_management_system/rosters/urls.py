
from django.contrib import admin
from django.urls import path,include

from .views import (AddShifts,StaffDetails,ViewShifts,MarkAttendance)

urlpatterns = [
    path("shift/", AddShifts.as_view()),
    path("edit-staff-details/", StaffDetails.as_view()),
    path("view-shifts/", ViewShifts.as_view()),
    path("markattendance/", MarkAttendance.as_view()),



]

