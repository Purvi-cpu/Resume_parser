# Generated by Django 5.1.2 on 2025-05-03 13:24

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('parserapp', '0006_otprecord'),
    ]

    operations = [
        migrations.CreateModel(
            name='Resume',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('file', models.FileField(upload_to='resumes/')),
                ('name', models.CharField(max_length=255)),
                ('uploaded_at', models.DateTimeField(auto_now_add=True)),
                ('status', models.CharField(default='pending', max_length=20)),
                ('parsed_data', models.JSONField(blank=True, null=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='resumes', to='parserapp.user')),
            ],
            options={
                'db_table': 'resumes',
                'ordering': ['-uploaded_at'],
            },
        ),
    ]
