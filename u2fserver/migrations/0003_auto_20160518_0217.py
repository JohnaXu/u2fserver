# -*- coding: utf-8 -*-
# Generated by Django 1.9.5 on 2016-05-18 02:17
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('u2fserver', '0002_user_appid'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='userName',
            field=models.CharField(max_length=64),
        ),
    ]