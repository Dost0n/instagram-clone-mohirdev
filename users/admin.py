from django.contrib import admin
from users.models import User, UserConfirmation



admin.site.register(User)
admin.site.register(UserConfirmation)