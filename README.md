# AttendanceManagementSystem

steps for to run the project

create virtual env by using command
pythom -m venv env

install the packages by usinng command
pip install -r requirements.txt

make migrations 
python manage.py migrate

add your mongo credentials in settings file.

run below command to run the server
python manage.py runserver 
