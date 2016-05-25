from __future__ import unicode_literals

from django.db import models

# Create your models here.
class User(models.Model):
    userName = models.CharField(max_length=64)
    challenge = models.CharField(max_length=64)
    key_handle = models.CharField(max_length=100)
    public_key = models.CharField(max_length=65)
    appId = models.CharField(max_length=64,default = 'http://localhost')
