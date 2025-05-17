from django.views.decorators.csrf import csrf_exempt
from django.http import HttpResponse
from django.template import loader
from django.http import JsonResponse
import json
from .models import User
from .models import OTPRecord
from .models import Profile
from .models import Resume
from django.contrib.auth import authenticate
from django.shortcuts import render, redirect, get_object_or_404
from django.views.decorators.http import require_GET
from django.contrib.auth.decorators import login_required, user_passes_test
import random
import string
from django.core.cache import cache
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from django.conf import settings
import PyPDF2
import docx
import re
import os
from django.core.files.storage import default_storage
from django.core.files.base import ContentFile
from datetime import datetime
from .models import SelectedResume
from .models import FormData

@csrf_exempt
def login(request):
    return render(request,'login.html')

@csrf_exempt
def register(request):
    return render(request,'registration.html')

def userdashboard(request):
    if request.method == 'GET':
        try:
            # Get user_id from session
            user_id = request.session.get('user_id')
            if not user_id:
                return JsonResponse({'status': False, 'message': 'User not authenticated'}, status=401)

            # Get user and profile data
            try:
                user = User.objects.get(id=user_id)
                profile = Profile.objects.get(user=user)
                
                # Get resume statistics
                total_resumes = Resume.objects.filter(user=user).count()
                last_uploaded = Resume.objects.filter(user=user).order_by('-uploaded_at').first()
                last_uploaded_date = last_uploaded.uploaded_at.strftime('%B %d, %Y') if last_uploaded else 'No resumes yet'
                
                context = {
                    'user': {
                        'id': user.id,
                        'username': user.username,
                        'email': user.email,
                        'mobile': user.mobile,
                        'role': user.role,
                        'is_verified': user.is_verified,
                    },
                    'profile': {
                        'name': profile.name,
                        'bio': profile.bio,
                        'image_url': profile.image.url if profile.image else None,
                    },
                    'total_resumes': total_resumes,
                    'last_uploaded': last_uploaded_date
                }
                return render(request, 'userdashboard.html', context)
                
            except User.DoesNotExist:
                return JsonResponse({'status': False, 'message': 'User not found'}, status=404)
            except Profile.DoesNotExist:
                # If profile doesn't exist, render dashboard with just user data
                total_resumes = Resume.objects.filter(user=user).count()
                last_uploaded = Resume.objects.filter(user=user).order_by('-uploaded_at').first()
                last_uploaded_date = last_uploaded.uploaded_at.strftime('%B %d, %Y') if last_uploaded else 'No resumes yet'
                
                context = {
                    'user': {
                        'id': user.id,
                        'username': user.username,
                        'email': user.email,
                        'mobile': user.mobile,
                        'role': user.role,
                        'is_verified': user.is_verified,
                    },
                    'profile': None,
                    'total_resumes': total_resumes,
                    'last_uploaded': last_uploaded_date
                }
                return render(request, 'userdashboard.html', context)
                
        except Exception as e:
            return JsonResponse({'status': False, 'message': str(e)}, status=500)
    
    return JsonResponse({'status': False, 'message': 'Only GET method allowed'}, status=405)

@csrf_exempt
def createprofile(request):
    return render(request,'createprofile.html')

@csrf_exempt
def update_profile(request):
    return render(request,'update_profile.html')

@csrf_exempt
def updateprofile(request):
    if request.method == 'GET':
        # Get user_id from session
        user_id = request.session.get('user_id')
        if not user_id:
            return JsonResponse({'status': False, 'message': 'User not authenticated'}, status=401)

        try:
            user = User.objects.get(id=user_id)
            try:
                profile = Profile.objects.get(user=user)
                context = {
                    'user': user,
                    'profile': profile
                }
            except Profile.DoesNotExist:
                context = {
                    'user': user,
                    'profile': None
                }
            return render(request, 'updateprofile.html', context)
        except User.DoesNotExist:
            return JsonResponse({'status': False, 'message': 'User not found'}, status=404)

    elif request.method == 'POST':
        # Get user_id from session
        user_id = request.session.get('user_id')
        if not user_id:
            return JsonResponse({'status': False, 'message': 'User not authenticated'}, status=401)

        name = request.POST.get('name')
        bio = request.POST.get('bio')
        image = request.FILES.get('image')

        try:
            profile = Profile.objects.get(user_id=user_id)
            if name: profile.name = name
            if bio: profile.bio = bio
            if image: profile.image = image
            profile.save()
            
            return JsonResponse({
                'status': True, 
                'message': 'Profile updated successfully.',
                'profile': {
                    'name': profile.name,
                    'bio': profile.bio,
                    'image_url': profile.image.url if profile.image else None,
                }
            })
        except Profile.DoesNotExist:
            # If profile doesn't exist, create one
            try:
                user = User.objects.get(id=user_id)
                profile = Profile.objects.create(
                    user=user,
                    name=name or user.username,
                    bio=bio or '',
                    image=image
                )
                return JsonResponse({
                    'status': True, 
                    'message': 'Profile created successfully.',
                    'profile': {
                        'name': profile.name,
                        'bio': profile.bio,
                        'image_url': profile.image.url if profile.image else None,
                    }
                })
            except User.DoesNotExist:
                return JsonResponse({'status': False, 'message': 'User not found.'}, status=404)
    
    return JsonResponse({'status': False, 'message': 'Invalid request method.'}, status=405)

# username,email,password,mobile,is_verified,role,
@csrf_exempt
def register_user(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body.decode('utf-8'))
            username = data.get('username', '').strip()
            email = data.get('email', '').strip()
            password = data.get('password', '').strip()
            mobile = data.get('mobile', '').strip()
            role = data.get('role', '').strip()

            errors = {}

            if not email:
                errors['email'] = 'Email is required.'
            if not password:
                errors['password'] = 'Password is required.'
            if not mobile:
                errors['mobile'] = 'Mobile number is required.'
            if not role:
                errors['role'] = 'Role is required.'

            if errors:
                return JsonResponse({'status': False, 'errors': errors}, status=400)

            # Check if email already exists
            if User.objects.filter(email=email).exists():
                return JsonResponse({'status': False, 'message': 'Email already exists.'}, status=409)

            # Create user with hashed password
            user = User.objects.create(
                username=username,
                email=email,
                mobile=mobile,
                role=role
            )
            user.set_password(password)  # This will hash the password
            user.save()

            return JsonResponse({'status': True, 'message': 'User registered successfully'}, status=201)

        except json.JSONDecodeError:
            return JsonResponse({'status': False, 'message': 'Invalid JSON'}, status=400)

    return JsonResponse({'status': False, 'message': 'Only POST method allowed'}, status=405)

@csrf_exempt
def login_user(request):
    try:
        data = json.loads(request.body)
        email = data.get("email")
        password = data.get("password")
        
        print("\n=== Login Attempt ===")
        print(f"Email: {email}")
        
        if not email or not password:
            print("Missing email or password")
            return JsonResponse({
                "status": False, 
                "message": "Email and password are required"
            }, status=400)

        try:
            user = User.objects.get(email=email)
            print(f"User found in database: {user.email}")
            print(f"User role: {user.role}")
            print(f"User is_verified: {user.is_verified}")
            
            if not user.check_password(password):
                print("Password check failed")
                return JsonResponse({
                    "status": False, 
                    "message": "Invalid email or password"
                }, status=401)

            print("Password check passed")
            
            # Clear any existing session data
            request.session.flush()
            
            # Set new session data
            request.session['user_id'] = user.id
            request.session['email'] = user.email
            request.session['role'] = user.role.lower()  # Store role in lowercase
            request.session['is_verified'] = user.is_verified
            request.session.save()  # Ensure session is saved
            
            print("Session data set:")
            print(f"user_id: {request.session.get('user_id')}")
            print(f"email: {request.session.get('email')}")
            print(f"role: {request.session.get('role')}")
            print(f"is_verified: {request.session.get('is_verified')}")
            
            user_data = {
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "mobile": user.mobile,
                "role": user.role,
                "is_verified": user.is_verified
            }
            
            # Case-insensitive role check
            if user.role.lower() == 'admin':
                print("Admin user detected")
                response = JsonResponse({
                    "status": True, 
                    "message": "Login successful", 
                    "user": user_data,
                    "redirect": "/admin_dashboard/"
                })
                print("Sending admin redirect response")
                return response
            
            if not user.is_verified:
                print("Unverified user detected")
                return JsonResponse({
                    "status": True,
                    "message": "OTP verification required",
                    "user": user_data,
                    "redirect": "/otp_verification/"
                })
            
            print("Verified regular user detected")
            return JsonResponse({
                "status": True, 
                "message": "Login successful", 
                "user": user_data,
                "redirect": "/userdashboard/"
            })

        except User.DoesNotExist:
            print(f"No user found with email: {email}")
            return JsonResponse({
                "status": False, 
                "message": "Invalid email or password"
            }, status=401)

    except json.JSONDecodeError:
        print("Invalid JSON data received")
        return JsonResponse({
            "status": False, 
            "message": "Invalid JSON data"
        }, status=400)
    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        return JsonResponse({
            "status": False, 
            "message": "Server error", 
            "error": str(e)
        }, status=500)


@csrf_exempt
@require_GET
def get_users(request):
    print("\n=== Get Users Request ===")
    print(f"Session data: {request.session.items()}")
    print(f"Headers: {request.headers}")
    
    # Check if user is logged in using our custom session
    if not request.session.get('user_id'):
        print("No user_id in session")
        if request.headers.get('x-requested-with') == 'XMLHttpRequest':
            return JsonResponse({'status': False, 'message': 'Not authenticated'}, status=401)
        return redirect('login')
    
    try:
        # Get user from our custom session
        user = User.objects.get(id=request.session['user_id'])
        print(f"User found: {user.email}, role: {user.role}")
        
        # Check if user is admin
        if user.role.lower() != 'admin':
            print(f"User {user.email} is not admin")
            if request.headers.get('x-requested-with') == 'XMLHttpRequest':
                return JsonResponse({'status': False, 'message': 'Not authorized'}, status=403)
            return redirect('userdashboard')
        
        # Get all non-admin users
        users = User.objects.exclude(role__iexact='admin').values(
            'id', 'username', 'email', 'mobile', 'is_verified', 'role'
        )
        user_list = list(users)
        print(f"Found {len(user_list)} users")
        
        response = JsonResponse({
            'status': True, 
            'users': user_list
        })
        response['Content-Type'] = 'application/json'
        return response
        
    except User.DoesNotExist:
        print("User not found in database")
        request.session.flush()  # Clear invalid session
        if request.headers.get('x-requested-with') == 'XMLHttpRequest':
            return JsonResponse({'status': False, 'message': 'User not found'}, status=404)
        return redirect('login')
    except Exception as e:
        print(f"Error getting users: {str(e)}")
        if request.headers.get('x-requested-with') == 'XMLHttpRequest':
            return JsonResponse({'status': False, 'message': str(e)}, status=500)
        return redirect('login')

@csrf_exempt
def create_profile(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Only POST method allowed'}, status=405)

    user_id = request.POST.get('user_id')
    name = request.POST.get('name')
    bio = request.POST.get('bio')
    image = request.FILES.get('image')

    if not user_id or not name:
        return JsonResponse({'error': 'user_id and name are required'}, status=400)

    try:
        user = User.objects.get(id=int(user_id))
    except (User.DoesNotExist, ValueError):
        return JsonResponse({'error': 'Invalid or missing user'}, status=404)

    if Profile.objects.filter(user=user).exists():
        return JsonResponse({'error': 'Profile already exists for this user'}, status=400)

    profile = Profile.objects.create(
        user=user,
        name=name,
        bio=bio,
        image=image
    )

    return JsonResponse({
        'message': 'Profile created successfully',
        'profile': {
            'user_id': user.id,
            'name': profile.name,
            'bio': profile.bio,
            'image_url': profile.image.url if profile.image else None,
        }
    }, status=201)

@csrf_exempt
def delete_profile(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body.decode('utf-8'))
            user_id = data.get('user_id')
            
            if not user_id:
                return JsonResponse({'status': False, 'message': 'User ID is required.'}, status=400)

            try:
                profile = Profile.objects.get(user_id=user_id)
                profile.delete()
                return JsonResponse({'status': True, 'message': 'Profile deleted successfully.'})
            except Profile.DoesNotExist:
                return JsonResponse({'status': False, 'message': 'Profile not found.'}, status=404)
                
        except json.JSONDecodeError:
            return JsonResponse({'status': False, 'message': 'Invalid JSON data.'}, status=400)

    return JsonResponse({'status': False, 'message': 'Invalid request method.'}, status=405)


@login_required
def get_user_profile_api(request):
    user = request.user
    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return JsonResponse({'error': 'User not found'}, status=404)

    try:
        profile = Profile.objects.get(user=user)
    except Profile.DoesNotExist:
        return JsonResponse({'error': 'Profile not found'}, status=404)

    data = {
        'user_id': user.id,
        'email': user.email,
        'mobile': user.mobile,
        'name': profile.name,
        'bio': profile.bio,
        'image_url': request.build_absolute_uri(profile.image.url) if profile.image else None,
    }

    return JsonResponse(data, status=200,)


def get_all_profiles(request):
    if request.method != 'GET':
        return JsonResponse({'error': 'Only GET method allowed'}, status=405)

    profiles = Profile.objects.select_related('user').all()

    data = []
    for profile in profiles:
        data.append({
            'user_id': profile.user.id,
            'username': profile.user.username,
            'name': profile.name,
            'bio': profile.bio,
            'image_url': profile.image.url if profile.image else None,
        })

    return JsonResponse({'profiles': data}, status=200)


@csrf_exempt
def delete_user(request,user_id):
    if request.method not in ['POST', 'DELETE']:
        return JsonResponse({'error': 'Only POST or DELETE method allowed'}, status=405)

    try:
        user = User.objects.get(id=int(user_id))
    except (User.DoesNotExist, ValueError):
        return JsonResponse({'error': 'Invalid or non-existent user'}, status=404)

    user.delete()

    return JsonResponse({'message': f'User {user.username} (ID {user_id}) deleted successfully'}, status=200)


@csrf_exempt
def update_user(request,user_id):
    if request.method != 'PUT':
        return JsonResponse({'error': 'Only POST method allowed'}, status=405)

    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)

    # user_id = data.get('user_id')
    # if not user_id:
    #     return JsonResponse({'error': 'user_id is required'}, status=400)

    try:
        user = User.objects.get(id=int(user_id))
    except (User.DoesNotExist, ValueError):
        return JsonResponse({'error': 'Invalid or non-existent user'}, status=404)

    # Optional fields to update
    username = data.get('username')
    first_name = data.get('first_name')
    last_name = data.get('last_name')
    email = data.get('email')
    password = data.get('password')

    # Custom fields
    mobile = data.get('mobile')
    role = data.get('role')

    if username:
        user.username = username
    if first_name:
        user.first_name = first_name
    if last_name:
        user.last_name = last_name
    if email:
        user.email = email
    if mobile:
        user.mobile = mobile
    if role:
        user.role = role
    if password:
        user.set_password(password)  # Always use set_password for hashing


    user.save()

    return JsonResponse({
        'message': f'User {user_id} updated successfully',
        'user': {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'mobile': user.mobile,
            'role': user.role,
        }})

@csrf_exempt
def generate_otp(request):
    if request.method == "POST":
        try:
            # Parse incoming JSON data
            data = json.loads(request.body)
            email = data.get("email")

            if not email:
                return JsonResponse({"status": False, "message": "Email is required"}, status=400)

             # Generate 6-digit OTP
            otp = ''.join(random.choices(string.digits, k=6))
            
              # Save OTP to database (optional: delete existing ones first)
            OTPRecord.objects.filter(email=email).delete()  # one active OTP per email
            OTPRecord.objects.create(email=email, otp=otp)

            # Store OTP in cache with 5 minutes expiry
            cache.set(f'otp_{email}', otp, 1000)  # 300 seconds = 5 minutes
            
            # Send OTP via SendGrid
            try:
                sg = SendGridAPIClient(settings.SENDGRID_API_KEY)
                message = Mail(
                    from_email=settings.SENDGRID_SENDER_EMAIL,
                    to_emails=email,
                    subject='Your OTP for Verification',
                    html_content=f'<strong>Your OTP is: {otp}</strong><br>This OTP will expire in 5 minutes.'
                )
                response = sg.send(message)
                
                return JsonResponse({
                    'status': True,
                    'message': 'OTP sent successfully'
                })
            except Exception as e:
                return JsonResponse({
                    'status': False,
                    'message': f'Failed to send OTP: {str(e)}'
                }, status=500)

            
        
        except json.JSONDecodeError:
            return JsonResponse({"status": False, "message": "Invalid JSON"}, status=400)

    return JsonResponse({"status": False, "message": "Invalid request method"}, status=405)

@csrf_exempt
def verify_otp(request):
    if request.method == 'POST':
        try:
            # Parse JSON data
            data = json.loads(request.body)
            email = data.get('email')
            otp = data.get('otp')
            
            if not email or not otp:
                return JsonResponse({'status': False, 'message': 'Email and OTP are required'}, status=400)
            
            try:
                # Check OTP in database
                otp_record = OTPRecord.objects.get(email=email, otp=otp)
                
                # Update user verification status
                user = User.objects.get(email=email)
                user.is_verified = True
                user.save()
                
                # Delete used OTP
                otp_record.delete()
                
                # Set session variables
                request.session['email'] = email
                request.session['user_id'] = user.id
                request.session['is_verified'] = True
                request.session['role'] = user.role
                
                # Determine redirect URL based on role
                redirect_url = '/admin_dashboard/' if user.role == 'admin' else '/userdashboard/'
                
                return JsonResponse({
                    'status': True,
                    'message': 'OTP verified successfully',
                    'redirect': redirect_url
                })
            except OTPRecord.DoesNotExist:
                return JsonResponse({'status': False, 'message': 'Invalid OTP'}, status=400)
            except User.DoesNotExist:
                return JsonResponse({'status': False, 'message': 'User not found'}, status=404)
                
        except json.JSONDecodeError:
            return JsonResponse({'status': False, 'message': 'Invalid JSON data'}, status=400)
    
    return JsonResponse({'status': False, 'message': 'Only POST method allowed'}, status=405)

def otp_verification(request):
    if request.method == 'GET':
        # Get email from session
        email = request.session.get('email')
        if not email:
            return redirect('login')  # Redirect to login if no email in session
            
        context = {
            'email': email
        }
        return render(request, 'otp_verification.html', context)
    return JsonResponse({'status': False, 'message': 'Only GET method allowed'}, status=405)

@csrf_exempt
def logout(request):
    if request.method == 'POST':
        try:
            # Clear all session data
            request.session.flush()
            return JsonResponse({'status': True, 'message': 'Logged out successfully'})
        except Exception as e:
            return JsonResponse({'status': False, 'message': str(e)}, status=500)
    return JsonResponse({'status': False, 'message': 'Only POST method allowed'}, status=405)

@csrf_exempt
def upload_resume(request):
    if request.method == 'POST':
        try:
            # Get user_id from session
            user_id = request.session.get('user_id')
            if not user_id:
                return JsonResponse({'status': False, 'message': 'User not authenticated'}, status=401)

            # Get the uploaded file
            resume_file = request.FILES.get('resume_file')
            if not resume_file:
                return JsonResponse({'status': False, 'message': 'No file uploaded'}, status=400)

            # Validate file type
            if not resume_file.name.endswith(('.pdf', '.docx')):
                return JsonResponse({'status': False, 'message': 'Invalid file type. Please upload PDF or DOCX'}, status=400)

            try:
                user = User.objects.get(id=user_id)
                
                # Create Resume record
                resume = Resume.objects.create(
                    user=user,
                    file=resume_file,
                    name=resume_file.name,
                    status='pending'
                )

                # Parse the resume
                parsed_data = {}
                if resume_file.name.endswith('.pdf'):
                    parsed_data = parse_pdf(resume.file.path)
                else:
                    parsed_data = parse_docx(resume.file.path)

                # Update resume with parsed data
                resume.parsed_data = parsed_data
                resume.status = 'parsed'
                resume.save()

                # Update user profile with parsed data
                profile, created = Profile.objects.get_or_create(user=user)
                if 'name' in parsed_data:
                    profile.name = parsed_data['name']
                if 'email' in parsed_data:
                    user.email = parsed_data['email']
                if 'phone' in parsed_data:
                    user.mobile = parsed_data['phone']
                if 'skills' in parsed_data:
                    profile.bio = f"Skills: {', '.join(parsed_data['skills'])}"
                
                profile.save()
                user.save()

                return JsonResponse({
                    'status': True,
                    'message': 'Resume parsed successfully',
                    'data': parsed_data
                })

            except Exception as e:
                if 'resume' in locals():
                    resume.status = 'error'
                    resume.save()
                return JsonResponse({'status': False, 'message': str(e)}, status=500)

        except Exception as e:
            return JsonResponse({'status': False, 'message': str(e)}, status=500)

    return JsonResponse({'status': False, 'message': 'Only POST method allowed'}, status=405)

def parse_pdf(file_path):
    parsed_data = {}
    try:
        with open(file_path, 'rb') as file:
            pdf_reader = PyPDF2.PdfReader(file)
            text = ""
            for page in pdf_reader.pages:
                text += page.extract_text()

            # Extract information using regex patterns
            parsed_data = extract_info_from_text(text)
    except Exception as e:
        raise Exception(f"Error parsing PDF: {str(e)}")
    return parsed_data

def parse_docx(file_path):
    parsed_data = {}
    try:
        doc = docx.Document(file_path)
        text = "\n".join([paragraph.text for paragraph in doc.paragraphs])
        parsed_data = extract_info_from_text(text)
    except Exception as e:
        raise Exception(f"Error parsing DOCX: {str(e)}")
    return parsed_data

def extract_info_from_text(text):
    data = {}
    
    # Extract name (first line or after "Name:")
    name_pattern = r'(?:Name:|^)([^\n]+)'
    name_match = re.search(name_pattern, text, re.IGNORECASE)
    if name_match:
        data['name'] = name_match.group(1).strip()

    # Extract email
    email_pattern = r'[\w\.-]+@[\w\.-]+\.\w+'
    email_match = re.search(email_pattern, text)
    if email_match:
        data['email'] = email_match.group(0)

    # Extract phone number
    phone_pattern = r'(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}'
    phone_match = re.search(phone_pattern, text)
    if phone_match:
        data['phone'] = phone_match.group(0)

    # Extract skills (look for common skill keywords)
    skills_keywords = ['python', 'java', 'javascript', 'html', 'css', 'sql', 'django', 'react', 'node', 'aws', 'git']
    found_skills = []
    for skill in skills_keywords:
        if re.search(rf'\b{skill}\b', text, re.IGNORECASE):
            found_skills.append(skill)
    if found_skills:
        data['skills'] = found_skills

    return data

def get_user_resumes(request):
    if request.method == 'GET':
        try:
            user_id = request.session.get('user_id')
            if not user_id:
                return JsonResponse({'status': False, 'message': 'User not authenticated'}, status=401)

            resumes = Resume.objects.filter(user_id=user_id).values(
                'id', 'name', 'uploaded_at', 'status', 'parsed_data'
            )
            return JsonResponse({
                'status': True,
                'resumes': list(resumes)
            })
        except Exception as e:
            return JsonResponse({'status': False, 'message': str(e)}, status=500)
    return JsonResponse({'status': False, 'message': 'Only GET method allowed'}, status=405)

def review_resume(request, resume_id=None):
    if request.method == 'GET':
        try:
            user_id = request.session.get('user_id')
            if not user_id:
                return JsonResponse({'status': False, 'message': 'User not authenticated'}, status=401)

            # Get the specific resume if ID is provided, otherwise get the latest
            if resume_id:
                resume = Resume.objects.get(id=resume_id, user_id=user_id)
            else:
                resume = Resume.objects.filter(user_id=user_id).order_by('-uploaded_at').first()
            
            if not resume:
                return JsonResponse({'status': False, 'message': 'No resume found'}, status=404)

            context = {
                'resume': {
                    'id': resume.id,
                    'name': resume.name,
                    'parsed_data': resume.parsed_data,
                    'uploaded_at': resume.uploaded_at
                }
            }
            return render(request, 'review_resume.html', context)

        except Resume.DoesNotExist:
            return JsonResponse({'status': False, 'message': 'Resume not found'}, status=404)
        except Exception as e:
            return JsonResponse({'status': False, 'message': str(e)}, status=500)

    return JsonResponse({'status': False, 'message': 'Only GET method allowed'}, status=405)

def check_auth(request):
    """
    Check if the user is authenticated and return the status as JSON.
    """
    return JsonResponse({
        'is_authenticated': request.user.is_authenticated
    })

def home(request):
    """
    View function to render the home page.
    """
    return render(request, 'Home_page.html')

def about(request):
    """
    View function to render the about page.
    """
    return render(request, 'about.html')

def contact(request):
    """
    View function to render the contact page.
    """
    return render(request, 'contact.html')

@csrf_exempt
def save_selected_resume(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            resume_id = data.get('resume_id')
            name = data.get('name')
            parsed_data = data.get('parsed_data', {})
            replace_existing = data.get('replace_existing', False)

            if not resume_id or not name:
                return JsonResponse({'status': False, 'message': 'Resume ID and name are required'}, status=400)

            # Get user from session
            user_id = request.session.get('user_id')
            if not user_id:
                return JsonResponse({'status': False, 'message': 'User not authenticated'}, status=401)

            try:
                user = User.objects.get(id=user_id)
                resume = Resume.objects.get(id=resume_id, user=user)

                # Check for existing resume with same name
                existing_resume = SelectedResume.objects.filter(user=user, name=name).first()
                
                if existing_resume and not replace_existing:
                    return JsonResponse({
                        'status': False,
                        'message': 'A resume with this name already exists',
                        'duplicate': True,
                        'existing_id': existing_resume.id
                    }, status=409)

                # Update the resume's parsed data with the form data
                if parsed_data:
                    current_data = resume.parsed_data or {}
                    current_data.update(parsed_data)
                    resume.parsed_data = current_data
                    resume.save()

                if existing_resume and replace_existing:
                    # Delete the existing resume first
                    existing_resume.delete()
                    # Create new selected resume
                    selected_resume = SelectedResume.objects.create(
                        user=user,
                        resume=resume,
                        name=name
                    )
                else:
                    # Create new selected resume
                    selected_resume = SelectedResume.objects.create(
                        user=user,
                        resume=resume,
                        name=name
                    )

                return JsonResponse({
                    'status': True,
                    'message': 'Resume saved successfully',
                    'resume_id': selected_resume.id
                })

            except User.DoesNotExist:
                return JsonResponse({'status': False, 'message': 'User not found'}, status=404)
            except Resume.DoesNotExist:
                return JsonResponse({'status': False, 'message': 'Resume not found'}, status=404)

        except json.JSONDecodeError:
            return JsonResponse({'status': False, 'message': 'Invalid JSON data'}, status=400)

    return JsonResponse({'status': False, 'message': 'Only POST method allowed'}, status=405)

@csrf_exempt
def delete_selected_resume(request, resume_id):
    if request.method == 'POST':
        try:
            user_id = request.session.get('user_id')
            if not user_id:
                return JsonResponse({'status': False, 'message': 'User not authenticated'}, status=401)

            try:
                # Get the selected resume
                selected_resume = SelectedResume.objects.get(id=resume_id, user_id=user_id)
                
                # Delete the selected resume
                selected_resume.delete()
                
                return JsonResponse({
                    'status': True,
                    'message': 'Resume deleted successfully'
                })
            except SelectedResume.DoesNotExist:
                return JsonResponse({
                    'status': False,
                    'message': 'Selected resume not found'
                }, status=404)

        except Exception as e:
            return JsonResponse({
                'status': False,
                'message': str(e)
            }, status=500)

    return JsonResponse({
        'status': False,
        'message': 'Only POST method allowed'
    }, status=405)

def get_selected_resumes(request):
    if request.method == 'GET':
        try:
            user_id = request.session.get('user_id')
            if not user_id:
                return JsonResponse({'status': False, 'message': 'User not authenticated'}, status=401)

            selected_resumes = SelectedResume.objects.filter(user_id=user_id).select_related('resume').values(
                'id',
                'name',
                'created_at',
                'resume__parsed_data'
            )
            
            return JsonResponse({
                'status': True,
                'resumes': list(selected_resumes)
            })

        except Exception as e:
            return JsonResponse({'status': False, 'message': str(e)}, status=500)

    return JsonResponse({'status': False, 'message': 'Only GET method allowed'}, status=405)

def view_selected_resume(request, resume_id):
    if request.method == 'GET':
        try:
            user_id = request.session.get('user_id')
            if not user_id:
                return JsonResponse({'status': False, 'message': 'User not authenticated'}, status=401)

            try:
                selected_resume = SelectedResume.objects.get(id=resume_id, user_id=user_id)
                context = {
                    'resume': {
                        'id': selected_resume.id,
                        'name': selected_resume.name,
                        'created_at': selected_resume.created_at,
                        'parsed_data': selected_resume.resume.parsed_data
                    }
                }
                return render(request, 'view_selected_resume.html', context)
            except SelectedResume.DoesNotExist:
                return JsonResponse({'status': False, 'message': 'Selected resume not found'}, status=404)

        except Exception as e:
            return JsonResponse({'status': False, 'message': str(e)}, status=500)

    return JsonResponse({'status': False, 'message': 'Only GET method allowed'}, status=405)

def list_selected_resumes(request):
    if request.method == 'GET':
        try:
            user_id = request.session.get('user_id')
            if not user_id:
                return JsonResponse({'status': False, 'message': 'User not authenticated'}, status=401)

            # Get all selected resumes for the user
            selected_resumes = SelectedResume.objects.filter(user_id=user_id).select_related('resume').values(
                'id',
                'name',
                'created_at',
                'resume__parsed_data'
            )
            
            context = {
                'resumes': selected_resumes,
                'debug': settings.DEBUG  # Include debug flag
            }
            return render(request, 'view_selected_resume.html', context)

        except Exception as e:
            return JsonResponse({'status': False, 'message': str(e)}, status=500)

    return JsonResponse({'status': False, 'message': 'Only GET method allowed'}, status=405)

@login_required
def fill_form(request):
    return render(request, 'fill_form.html')


@login_required
def get_selected_resume_data(request, resume_id):
    try:
        resume = SelectedResume.objects.get(id=resume_id)
        # Check if user has permission to view this resume
        if request.user.role != 'admin' and resume.user != request.user:
            return JsonResponse({'status': False, 'message': 'Unauthorized'}, status=403)
        
        return JsonResponse({
            'status': True,
            'resume': {
                'id': resume.id,
                'name': resume.name,
                'resume__parsed_data': resume.resume.parsed_data
            }
        })
    except SelectedResume.DoesNotExist:
        return JsonResponse({'status': False, 'message': 'Resume not found'}, status=404)

@login_required
def save_form_data(request):
    if request.method != 'POST':
        return JsonResponse({'status': False, 'message': 'Invalid request method'}, status=405)
    
    try:
        data = json.loads(request.body)
        # Create a new FormData instance
        form_data = FormData.objects.create(
            user=request.user,
            name=data.get('name', ''),
            email=data.get('email', ''),
            phone=data.get('phone', ''),
            skills=data.get('skills', []),
            experience=data.get('experience', ''),
            education=data.get('education', '')
        )
        return JsonResponse({
            'status': True,
            'message': 'Form data saved successfully',
            'form_id': form_data.id
        })
    except json.JSONDecodeError:
        return JsonResponse({'status': False, 'message': 'Invalid JSON data'}, status=400)
    except Exception as e:
        return JsonResponse({'status': False, 'message': str(e)}, status=500)

def is_admin(user):
    return user.is_staff


def admin_dashboard(request):
    print("\n=== Admin Dashboard Access Attempt ===")
    print("Session data:")
    print(f"user_id: {request.session.get('user_id')}")
    print(f"email: {request.session.get('email')}")
    print(f"role: {request.session.get('role')}")
    print(f"is_verified: {request.session.get('is_verified')}")
    
    # Check if user is logged in and has a session
    if not request.session.get('user_id'):
        print("No user_id in session, redirecting to login")
        return redirect('login')
    
    try:
        user = User.objects.get(id=request.session['user_id'])
        print(f"User found in database: {user.email}")
        print(f"User role from database: {user.role}")
        print(f"Session role: {request.session.get('role')}")
        
        # Case-insensitive role check
        if user.role.lower() != 'admin':
            print("User is not admin, redirecting to userdashboard")
            return redirect('userdashboard')
        
        # Set session data again to ensure it's fresh
        request.session['user_id'] = user.id
        request.session['email'] = user.email
        request.session['role'] = user.role.lower()
        request.session['is_verified'] = user.is_verified
        request.session.save()
        
        print("Admin access granted, rendering dashboard")
        return render(request, 'admin_dashboard.html', {'user': user})
        
    except User.DoesNotExist:
        print("User not found in database")
        request.session.flush()
        return redirect('login')
    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        request.session.flush()
        return redirect('login')


@user_passes_test(is_admin)
def get_all_resumes(request):
    resumes = Resume.objects.select_related('user').values(
        'id', 'name', 'uploaded_at', 'user__username'
    )
    return JsonResponse({'resumes': list(resumes)})


@user_passes_test(is_admin)
def delete_user(request, user_id):
    try:
        user = User.objects.get(id=user_id, is_staff=False)
        user.delete()
        return JsonResponse({'status': True, 'message': 'User deleted successfully'})
    except User.DoesNotExist:
        return JsonResponse({'status': False, 'message': 'User not found'})


@user_passes_test(is_admin)
def delete_resume(request, resume_id):
    try:
        resume = Resume.objects.get(id=resume_id)
        resume.delete()
        return JsonResponse({'status': True, 'message': 'Resume deleted successfully'})
    except Resume.DoesNotExist:
        return JsonResponse({'status': False, 'message': 'Resume not found'})


@csrf_exempt
def view_user_profile(request, user_id):
    print("\n=== View User Profile Request ===")
    print(f"Session data: {request.session.items()}")
    print(f"Target user_id: {user_id}")
    
    # Check if user is logged in
    if not request.session.get('user_id'):
        print("No user_id in session")
        return redirect('login')
    
    try:
        # Get admin user from session
        admin_user = User.objects.get(id=request.session['user_id'])
        print(f"Admin user found: {admin_user.email}, role: {admin_user.role}")
        
        # Check if user is admin
        if admin_user.role.lower() != 'admin':
            print(f"User {admin_user.email} is not admin")
            return redirect('userdashboard')
        
        # Get target user
        target_user = User.objects.get(id=user_id)
        print(f"Target user found: {target_user.email}")
        
        # Get user's resumes
        resumes = Resume.objects.filter(user=target_user)
        print(f"Found {resumes.count()} resumes for user")
        
        context = {
            'profile_user': target_user,
            'resumes': resumes,
            'admin_user': admin_user
        }
        return render(request, 'user_profile.html', context)
        
    except User.DoesNotExist:
        print("User not found in database")
        return JsonResponse({'status': False, 'message': 'User not found'}, status=404)
    except Exception as e:
        print(f"Error viewing user profile: {str(e)}")
        return JsonResponse({'status': False, 'message': str(e)}, status=500)


@csrf_exempt
def view_resume(request, resume_id):
    print("\n=== View Resume Request ===")
    print(f"Session data: {request.session.items()}")
    print(f"Resume ID: {resume_id}")
    
    # Check if user is logged in
    if not request.session.get('user_id'):
        print("No user_id in session")
        return redirect('login')
    
    try:
        # Get admin user from session
        admin_user = User.objects.get(id=request.session['user_id'])
        print(f"Admin user found: {admin_user.email}, role: {admin_user.role}")
        
        # Check if user is admin
        if admin_user.role.lower() != 'admin':
            print(f"User {admin_user.email} is not admin")
            return redirect('userdashboard')
        
        # Get the resume
        resume = Resume.objects.get(id=resume_id)
        print(f"Resume found: {resume.name}")
        
        # Get the user who owns the resume
        resume_user = resume.user
        print(f"Resume belongs to user: {resume_user.email}")
        
        context = {
            'resume': resume,
            'resume_user': resume_user,
            'admin_user': admin_user
        }
        return render(request, 'view_resume.html', context)
        
    except Resume.DoesNotExist:
        print("Resume not found")
        return JsonResponse({'status': False, 'message': 'Resume not found'}, status=404)
    except User.DoesNotExist:
        print("User not found")
        request.session.flush()
        return redirect('login')
    except Exception as e:
        print(f"Error viewing resume: {str(e)}")
        return JsonResponse({'status': False, 'message': str(e)}, status=500)

@csrf_exempt
def get_user_selected_resumes(request, user_id):
    print("\n=== Get User Selected Resumes Request ===")
    print(f"Session data: {request.session.items()}")
    print(f"Target user_id: {user_id}")
    
    # Check if user is logged in
    if not request.session.get('user_id'):
        print("No user_id in session")
        return JsonResponse({'status': False, 'message': 'Not authenticated'}, status=401)
    
    try:
        # Get admin user from session
        admin_user = User.objects.get(id=request.session['user_id'])
        print(f"Admin user found: {admin_user.email}, role: {admin_user.role}")
        
        # Check if user is admin
        if admin_user.role.lower() != 'admin':
            print(f"User {admin_user.email} is not admin")
            return JsonResponse({'status': False, 'message': 'Not authorized'}, status=403)
        
        # Get target user's resumes
        resumes = Resume.objects.filter(user_id=user_id).values('id', 'name', 'parsed_data')
        print(f"Found {resumes.count()} resumes for user")
        
        return JsonResponse({
            'status': True,
            'resumes': list(resumes)
        })
        
    except User.DoesNotExist:
        print("User not found in database")
        return JsonResponse({'status': False, 'message': 'User not found'}, status=404)
    except Exception as e:
        print(f"Error getting user resumes: {str(e)}")
        return JsonResponse({'status': False, 'message': str(e)}, status=500)

@csrf_exempt
def get_selected_resume_data(request, resume_id):
    print("\n=== Get Selected Resume Data Request ===")
    print(f"Session data: {request.session.items()}")
    print(f"Resume ID: {resume_id}")
    
    # Check if user is logged in
    if not request.session.get('user_id'):
        print("No user_id in session")
        return JsonResponse({'status': False, 'message': 'Not authenticated'}, status=401)
    
    try:
        # Get admin user from session
        admin_user = User.objects.get(id=request.session['user_id'])
        print(f"Admin user found: {admin_user.email}, role: {admin_user.role}")
        
        # Check if user is admin
        if admin_user.role.lower() != 'admin':
            print(f"User {admin_user.email} is not admin")
            return JsonResponse({'status': False, 'message': 'Not authorized'}, status=403)
        
        # Get the resume
        resume = Resume.objects.get(id=resume_id)
        print(f"Resume found: {resume.name}")
        
        # Get parsed data
        parsed_data = resume.parsed_data or {}
        
        return JsonResponse({
            'status': True,
            'data': {
                'name': parsed_data.get('name', ''),
                'email': parsed_data.get('email', ''),
                'phone': parsed_data.get('phone', ''),
                'skills': parsed_data.get('skills', []),
                'experience': parsed_data.get('experience', ''),
                'education': parsed_data.get('education', '')
            }
        })
        
    except Resume.DoesNotExist:
        print("Resume not found")
        return JsonResponse({'status': False, 'message': 'Resume not found'}, status=404)
    except Exception as e:
        print(f"Error getting resume data: {str(e)}")
        return JsonResponse({'status': False, 'message': str(e)}, status=500)

@csrf_exempt
def save_form_data(request):
    print("\n=== Save Form Data Request ===")
    print(f"Session data: {request.session.items()}")
    
    # Check if user is logged in
    if not request.session.get('user_id'):
        print("No user_id in session")
        return JsonResponse({'status': False, 'message': 'Not authenticated'}, status=401)
    
    if request.method != 'POST':
        return JsonResponse({'status': False, 'message': 'Invalid request method'}, status=405)
    
    try:
        # Get admin user from session
        admin_user = User.objects.get(id=request.session['user_id'])
        print(f"Admin user found: {admin_user.email}, role: {admin_user.role}")
        
        # Check if user is admin
        if admin_user.role.lower() != 'admin':
            print(f"User {admin_user.email} is not admin")
            return JsonResponse({'status': False, 'message': 'Not authorized'}, status=403)
        
        # Parse request data
        data = json.loads(request.body)
        print(f"Form data: {data}")
        
        # Create or update form data
        form_data, created = FormData.objects.update_or_create(
            user=admin_user,
            defaults={
                'name': data.get('name', ''),
                'email': data.get('email', ''),
                'phone': data.get('phone', ''),
                'skills': data.get('skills', []),
                'experience': data.get('experience', ''),
                'education': data.get('education', '')
            }
        )
        
        print(f"Form data {'created' if created else 'updated'}")
        
        return JsonResponse({
            'status': True,
            'message': 'Form data saved successfully',
            'form_id': form_data.id
        })
        
    except json.JSONDecodeError:
        print("Invalid JSON data")
        return JsonResponse({'status': False, 'message': 'Invalid JSON data'}, status=400)
    except Exception as e:
        print(f"Error saving form data: {str(e)}")
        return JsonResponse({'status': False, 'message': str(e)}, status=500)
