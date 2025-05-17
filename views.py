from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
import json
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login
from django.shortcuts import render

# All views have been moved to parserapp/views.py 