from django.core.management.base import BaseCommand
from parserapp.models import User

class Command(BaseCommand):
    help = 'Check if a specific user exists in the database'

    def handle(self, *args, **options):
        email = 'p95871334@gmail.com'
        try:
            user = User.objects.get(email=email)
            self.stdout.write(self.style.SUCCESS(f'User found: {user.email}'))
            self.stdout.write(f'Username: {user.username}')
            self.stdout.write(f'Password: {user.password}')  # This will show the hashed password
        except User.DoesNotExist:
            self.stdout.write(self.style.ERROR(f'User with email {email} not found')) 