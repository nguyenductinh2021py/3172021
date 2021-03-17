from django.db import models
from django.contrib.auth.models import AbstractUser

class User(AbstractUser):
    address = models.CharField(max_length=500, blank=True)
    avatar = models.ImageField(upload_to='avatar/', null=True, blank=True)
