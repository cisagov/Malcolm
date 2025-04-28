from users.models import Token, User
from os import getenv

# adapted from
# - https://github.com/netbox-community/netbox-docker/blob/release/docker/docker-entrypoint.sh

superUserName = getenv('SUPERUSER_NAME', '')
superUserEmail = getenv('SUPERUSER_EMAIL', '')
superUserPassword = getenv('SUPERUSER_PASSWORD', '')
superUserToken = getenv('SUPERUSER_API_TOKEN', getenv('NETBOX_TOKEN', ''))

if not User.objects.filter(username=superUserName):
    u = User.objects.create_superuser(superUserName, superUserEmail, superUserPassword)
    Token.objects.create(user=u, key=superUserToken)
