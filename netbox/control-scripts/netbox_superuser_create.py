import sys
from os import environ

from django.conf import settings
from users.choices import TokenVersionChoices
from users.models import Token, User


# Read secret from file
def _read_secret(secret_name: str, default: str | None = None) -> str | None:
    try:
        with open('/run/secrets/' + secret_name, encoding='utf-8') as f:
            return f.readline().strip()
    except OSError:
        return default


su_name = environ.get('SUPERUSER_NAME', 'admin')
su_email = environ.get('SUPERUSER_EMAIL', 'admin@example.com')
su_password = _read_secret('superuser_password', environ.get('SUPERUSER_PASSWORD'))
su_api_token = _read_secret('superuser_api_token', environ.get('SUPERUSER_API_TOKEN', environ.get('NETBOX_TOKEN')))
su_api_key = _read_secret('superuser_api_key', environ.get('SUPERUSER_API_KEY'))

if User.objects.filter(username=su_name).exists():
    print(f'User with name "{su_name}" already exists.')
    if not settings.API_TOKEN_PEPPERS and su_api_token:
        u = User.objects.get(username=su_name)
        if not Token.objects.filter(user=u).exclude(key=None).exists():
            Token.objects.filter(user=u).delete()
            t = Token.objects.create(user=u, token=su_api_token, version=TokenVersionChoices.V1)
            print(f'💡 Recreated missing/broken token for existing superuser.')
        else:
            print(f'💡 Token already exists, skipping.')
    sys.exit(0)

if not su_password:
    print(
        '⚠️ Warning: No superuser password provided. Please set the SUPERUSER_PASSWORD environment variable or provide a secret file. The superuser will not be created.'
    )
    sys.exit(0)

u = User.objects.create_superuser(su_name, su_email, su_password)
if not settings.API_TOKEN_PEPPERS:
    if su_api_token:
        t = Token.objects.create(user=u, token=su_api_token, version=TokenVersionChoices.V1)
        print(f'💡 Superuser Username: {su_name}, E-Mail: {su_email},')
        print(f"💡 API Token: use with '{t.get_auth_header_prefix()}<Your token>'")
    else:
        print('⚠️ No API token was created for the superuser as SUPERUSER_API_TOKEN is not set')
        print(f'💡 Superuser Username: {su_name}, E-Mail: {su_email}')
else:
    if su_api_key and su_api_token:
        t = Token.objects.create(user=u, token=su_api_token, version=TokenVersionChoices.V2, key=su_api_key)
        print(f'💡 Superuser Username: {su_name}, E-Mail: {su_email},')
        print(f"💡 API Token: use with '{t.get_auth_header_prefix()}<Your token>'")
    else:
        print('⚠️ No API token was created for the superuser as SUPERUSER_API_TOKEN and SUPERUSER_API_KEY are not set')
        print(f'💡 Superuser Username: {su_name}, E-Mail: {su_email}')
