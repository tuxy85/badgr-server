# -*- coding: utf-8 -*-
# Generated by Django 1.11.20 on 2019-04-05 20:44
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('badgeuser', '0021_auto_20190405_0921'),
    ]

    operations = [
        migrations.AlterField(
            model_name='userrecipientidentifier',
            name='type',
            field=models.CharField(choices=[('url', 'URL'), ('telephone', 'Phone Number')], default='url', max_length=9),
        ),
    ]