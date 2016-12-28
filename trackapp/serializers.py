from django.contrib.auth import update_session_auth_hash

from rest_framework import serializers

from trackapp.models import Usr,Geodata
import uuid
import random

"""
This is  Serializer clas for serialize usr fiels using modelSerializer
"""
class UsrSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=False)
    confirm_password = serializers.CharField(write_only=True, required=False)


    class Meta:
        model = Usr
        fields = ('id', 'email', 'username', 'created_at', 'updated_at',
                  'first_name', 'last_name','designation','address','contact','reset_id', 'password',
                  'confirm_password',)
        read_only_fields = ('created_at', 'updated_at',)


        # Override create method from Djangi User class(Defauld django core)
        def create(self, validated_data):

            return Usr.objects.njhjk(**validated_data)

        #Override update method from django User class (defauld django Core)
        def update(self, instance, validated_data):
            instance.username = validated_data.get('username', instance.username)
            instance.designation = validated_data.get('designation', instance.designation)
            instance.address = validated_data.get('address',instance.address)
            instance.contact = validated_data.get('contact',instance.contact)


            instance.save()

            password = validated_data.get('password', None)
            confirm_password = validated_data.get('confirm_password', None)

            if password and confirm_password and password == confirm_password:
                instance.set_password(password)
                instance.save()

            update_session_auth_hash(self.context.get('request'), instance)

            return instance

class PasswordResetSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=False, required=False)
    confirm_password = serializers.CharField(write_only=True, required=False)

    class Meta:
        model = Usr
        fields = ('id', 'reset_id', 'password',
                  'confirm_password',)

        #Override update method from django User class (defauld django Core)
        def update(self, instance, validated_data):



            password = validated_data.get('password', None)

            instance.set_password(password)
            instance.save()


            update_session_auth_hash(self.context.get('request'), instance)

            return instance


#serilaizer class for Geodata table
class GeodataSerializer(serializers.ModelSerializer):
    class Meta:
        model=Geodata
        fields = ('id','user_id','device_id','latitude','longitude','speed','time_stamp')