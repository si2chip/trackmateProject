# -*- coding: utf-8 -*-
# Generated by Django 1.10.2 on 2016-12-28 07:06
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('trackapp', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='Geodata',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('user_id', models.IntegerField(blank=True)),
                ('device_id', models.IntegerField(blank=True)),
                ('latitude', models.FloatField(blank=True)),
                ('longitude', models.FloatField(blank=True)),
                ('speed', models.FloatField(blank=True)),
                ('time_stamp', models.DateTimeField(auto_now_add=True)),
            ],
        ),
    ]