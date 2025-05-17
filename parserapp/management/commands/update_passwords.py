from django.core.management.base import BaseCommand
from parserapp.models import User

class Command(BaseCommand):
    help = 'Updates existing user passwords to use the new hashing system'

    def handle(self, *args, **options):
        users = User.objects.all()
        for user in users:
            # Get the current plain text password
            current_password = user.password
            # Set the password using the new hashing system
            user.set_password(current_password)
            user.save()
            self.stdout.write(self.style.SUCCESS(f'Updated password for user: {user.email}')) 