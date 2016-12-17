"""
WSGI config for trackmates project.

It exposes the WSGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/1.10/howto/deployment/wsgi/
"""

import os
import sys
sys.path.append('/home/bharat/trackmateProject')
sys.path.append('/home/bharat/trackmateProject/trackmates')

from django.core.wsgi import get_wsgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "trackmates.settings")

application = get_wsgi_application()
