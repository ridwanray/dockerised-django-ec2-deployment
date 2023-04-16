from datetime import timedelta
from .base import *


ALLOWED_HOSTS = config('ALLOWED_HOSTS', cast=lambda v: [s.strip() for s in v.split(',')])

sentry_sdk.init(
        dsn=config('SENTRY_DSN', None),
        integrations=[DjangoIntegration()],
        traces_sample_rate=1.0,
        send_default_pii=True
    )

# EMAIL CONFIG
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = config('EMAIL_HOST')
EMAIL_PORT = config('EMAIL_PORT', cast=int)
EMAIL_HOST_USER = config('EMAIL_HOST_USER')
EMAIL_HOST_PASSWORD = config('EMAIL_HOST_PASSWORD')
EMAIL_USE_SSL = config('EMAIL_USE_SSL', cast=bool)
DEFAULT_FROM_EMAIL = EMAIL_HOST_USER

CELERY_BROKER_URL = CELERY_BROKER_URL = config('CELERY_BROKER_URL')

APP_NAME = os.getenv("APP_NAME")
STATIC_ROOT = os.path.join(BASE_DIR, f"staticfiles/{APP_NAME}")
STATIC_TMP = os.path.join(BASE_DIR, f"static/{APP_NAME}")
os.makedirs(STATIC_TMP, exist_ok=True)
os.makedirs(STATIC_ROOT, exist_ok=True)

# AWS CONFIG
# to make sure all your files gives read only access to the files
STATICFILES_STORAGE = "storages.backends.s3boto3.S3Boto3Storage"
DEFAULT_FILE_STORAGE = "core.storage_backends.MediaStorage"
PRIVATE_MEDIA_LOCATION = "private"
PRIVATE_FILE_STORAGE = "core.storage_backends.PrivateMediaStorage"

AWS_DEFAULT_ACL = "public-read"
AWS_QUERYSTRING_AUTH = False
AWS_S3_REGION_NAME = os.environ.get("AWS_S3_REGION_NAME")
AWS_ACCESS_KEY_ID = os.environ.get("ACCESS_KEY_AWS")
AWS_SECRET_ACCESS_KEY = os.environ.get("ACCESS_SECRET_AWS")
AWS_STORAGE_BUCKET_NAME = os.environ.get("ACCESS_BUCKET_NAME_AWS")
AWS_S3_ENDPOINT_URL = f"https://{AWS_S3_REGION_NAME}.digitaloceanspaces.com"
AWS_S3_CUSTOM_DOMAIN = os.environ.get("AWS_S3_CUSTOM_DOMAIN")
AWS_S3_OBJECT_PARAMETERS = {
    "CacheControl": "max-age=86400",
}
AWS_LOCATION = f"static/{APP_NAME}"
AWS_S3_SIGNATURE_VERSION = "s3v4"
STATICFILES_DIRS = [
    BASE_DIR / AWS_LOCATION,
]

STATIC_URL = "{}/{}/".format(AWS_S3_CUSTOM_DOMAIN, AWS_LOCATION)
STATIC_ROOT = "static/"
