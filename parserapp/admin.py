from django.contrib import admin
from .models import *
# Register your models here.
admin.site.register(User)
admin.site.register(Profile)
admin.site.register(Resume)
admin.site.register(SelectedResume)
admin.site.register(FormData)