# -*- coding: utf-8 -*-
# Generated by Django 1.9.5 on 2016-05-18 02:12
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('u2fserver', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='appId',
            field=models.CharField(default='http://localhost', max_length=64),
        ),
    ]