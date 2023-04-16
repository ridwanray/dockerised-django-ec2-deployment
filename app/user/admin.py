from django.contrib import admin

from .models import Role, Token, User

# Register your models here.
admin.site.register(Role)
admin.site.register(User)
admin.site.register(Token)

