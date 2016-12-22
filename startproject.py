import os
import django
import subprocess as sub
#os.system("./manage.py runserver")
p=sub.Popen(["python","manage.py","runserver"],stdout=sub.PIPE,stderr=sub.PIPE)
output,errors=p.communicate()
print(output,errors)