from django.contrib.auth.models import User
from users.models import Token
from os import getenv

# adapted from
# - https://github.com/netbox-community/netbox-docker/blob/b47e85ab3f2261021adf99ae9de2e9692fd674c3/docker/docker-entrypoint.sh#L74-L80

superUserName = getenv('SUPERUSER_NAME', '')
superUserEmail = getenv('SUPERUSER_EMAIL', '')
superUserPassword = getenv('SUPERUSER_PASSWORD', '')
superUserToken = getenv('SUPERUSER_API_TOKEN', '')

if not User.objects.filter(username=superUserName):
    u = User.objects.create_superuser(superUserName, superUserEmail, superUserPassword)
    Token.objects.create(user=u, key=superUserToken)
