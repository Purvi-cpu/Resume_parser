# Generated by Django 5.1.2 on 2025-05-02 18:33

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('parserapp', '0005_profile_delete_userprofile'),
    ]

    operations = [
        migrations.CreateModel(
            name='OTPRecord',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('email', models.EmailField(max_length=254)),
                ('otp', models.CharField(max_length=6)),
            ],
        ),
    ]
