"""
Django settings for sessionServer project.

Generated by 'django-admin startproject' using Django 3.2.25.

For more information on this file, see
https://docs.djangoproject.com/en/3.2/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/3.2/ref/settings/
"""

from pathlib import Path
import os
import sys
from decouple import config
from celery.schedules import crontab

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/3.2/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = config('SECRET_KEY')

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = ['*']


# Application definition

INSTALLED_APPS = [
    'jazzmin',
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'rest_framework',
    'oauth2_provider',
    'session',
    'userauth', 
    "django_celery_beat",
]

REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'oauth2_provider.contrib.rest_framework.OAuth2Authentication',
        'rest_framework.authentication.SessionAuthentication',
    ),
    'DEFAULT_PERMISSION_CLASSES': (
        'rest_framework.permissions.IsAuthenticated',
    ),
    'DEFAULT_THROTTLE_CLASSES': [
        'rest_framework.throttling.AnonRateThrottle',
        'rest_framework.throttling.UserRateThrottle'
    ],
    'DEFAULT_THROTTLE_RATES': {
        'anon': '10/minute', 
        'user': '1000/day'   
    }
}

OAUTH2_PROVIDER = {
    'ACCESS_TOKEN_EXPIRE_SECONDS': 36000,
    'AUTHORIZATION_CODE_EXPIRE_SECONDS': 600,
    'APPLICATION_MODEL': 'oauth2_provider.Application',
    'GRANT_MODEL': 'oauth2_provider.Grant',
    'REFRESH_TOKEN_EXPIRE_SECONDS': 1209600,
    'SCOPES': {'read': 'Read scope', 'write': 'Write scope', 'groups': 'Access to your groups'},
    'OAUTH2_BACKEND_CLASS': 'oauth2_provider.oauth2_backends.OAuthLibCore',
    'OAUTH2_VALIDATOR_CLASS': 'oauth2_provider.oauth2_validators.OAuth2Validator',
    'OAUTH2_SERVER_CLASS': 'oauthlib.oauth2.Server'
}

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'session.middleware.request_middleware.RequestMiddleware',
    'middleware.ssl_middleware.SSLMiddleware',
]

ROOT_URLCONF = 'config.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'config.wsgi.application'


# Database
# https://docs.djangoproject.com/en/3.2/ref/settings/#databases


DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': config('POSTGRES_DB'),
        'USER': config('POSTGRES_USER'),
        'PASSWORD': config('POSTGRES_PASSWORD'),
        'HOST': config('POSTGRES_HOST'), 
        'PORT': '5432', 
    }
}

SESSION_ENGINE = 'django.contrib.sessions.backends.db'


# Password validation
# https://docs.djangoproject.com/en/3.2/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
    {
        'NAME': 'userauth.validators.CustomPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/3.2/topics/i18n/

LANGUAGE_CODE = 'pl'

TIME_ZONE = 'Europe/Warsaw'

USE_I18N = True

USE_L10N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/3.2/howto/static-files/

STATIC_URL = '/static/'

STATIC_ROOT = os.path.join(BASE_DIR, 'static/')

# Default primary key field type
# https://docs.djangoproject.com/en/3.2/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True

USE_X_FORWARDED_HOST = True
SECURE_SSL_REDIRECT = True
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')

SECURE_HSTS_SECONDS = 31536000  
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True  
SECURE_CONTENT_TYPE_NOSNIFF = True

SECURE_BROWSER_XSS_FILTER = True

COOKIE_NAME = "access"
COOKIE_SAMESITE = "Lax"
COOKIE_PATH = "/"
COOKIE_HTTPONLY = True
COOKIE_SECURE = True

STATIC_ROOT = os.path.join(BASE_DIR, 'static/')

AUTH_USER_MODEL = 'userauth.User'

SECRET_SERVER_URL = config('SECRET_SERVER_URL')

CSR_CERT_FILE = os.path.join(BASE_DIR,"cert","new","client.csr")
CONF_CERT_FILE = os.path.join(BASE_DIR,"cert","new","client_cert.cnf")
SECRET_CERT_PATH = os.path.join(BASE_DIR, 'cert',"new",'client.crt')
SECRET_KEY_PATH = os.path.join(BASE_DIR, 'cert',"new",'client.key')
CA_KEY_FILE = os.path.join(BASE_DIR,"cert","new","ca.key")
CA_CERT_PATH = os.path.join(BASE_DIR, 'cert',"new",'ca.crt')

MIN_EXPIRATION_HOURS = 1
MAX_EXPIRATION_HOURS = 2
CREATED_TOLERANCE_SECONDS = 5

CACHE_TIMEOUT = 600

SERVER_SALT = config("SERVER_SALT")

CELERY_BROKER_URL = config("CELERY_BROKER_URL")
CELERY_RESULT_BACKEND = config("CELERY_RESULT_BACKEND")
CELERY_ACCEPT_CONTENT = ["application/json"]
CELERY_TASK_SERIALIZER = "json"
CELERY_RESULT_SERIALIZER = "json"
CELERY_RESULT_BACKEND_MAX_RETRIES = 10

CELERY_TASK_SEND_SENT_EVENT = True
CELERY_RESULT_EXTENDED = True

CELERY_RESULT_BACKEND_ALWAYS_RETRY = True

CELERY_TASK_TIME_LIMIT = 5 * 60

CELERY_TASK_SOFT_TIME_LIMIT = 60

CELERY_BEAT_SCHEDULER = "django_celery_beat.schedulers:DatabaseScheduler"

CELERY_WORKER_SEND_TASK_EVENTS = True

CELERY_BEAT_SCHEDULE = {
    'check-redis-every-10-seconds': {
        'task': 'monitor_redis_connection',
        'schedule': crontab(minute='*/1'), 
    },
    'batch-insert-logs-every-10-minute': {
        'task': 'batch_insert_logs_task',
        'schedule': crontab(minute='*/10'), 
    },
    'delete_old_request_log-every-3-days': {
        'task': 'delete_old_request_log',
        'schedule': crontab(minute='0', hour='0', day_of_month='*/3'), 
    },
    'delete_expired_tokens-every-day': {
        'task': 'delete_expired_tokens',
        'schedule': crontab(minute='0', hour='0', day_of_week='*'), 
    },
}


AUTHENTICATION_BACKENDS = [
    'userauth.backends.UsernameOrEmailBackend', 
    "django.contrib.auth.backends.ModelBackend",
]

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    "formatters": {
        "verbose": {
            "format": "%(levelname)s %(name)-12s %(asctime)s %(module)s %(process)d %(thread)d %(message)s"
        }
    },
    'handlers': {
        'file': {
            'level': 'DEBUG',
            'class': 'logging.FileHandler',
            'filename':os.path.join(BASE_DIR, 'logs/django.log') ,
            'formatter': 'verbose', 
            'mode': 'a',
        },
        'console': {
            'level': 'DEBUG',
            'class': 'logging.StreamHandler',
            'stream': sys.stdout,
            'formatter': 'verbose', 
        },
    },
    'loggers': {
        'django': {
            'handlers': ['file', 'console'],
            'level': 'DEBUG',
            'propagate': True,
        },
        'test_logger': {
            'handlers': ['console'],
            'level': 'DEBUG',  
            'propagate': False,
        },
        'django.request': {
            'handlers': ['console'],
            'level': 'DEBUG',
            'propagate': True,
        },
        'django.db.backends.schema': { 
            'handlers': ['console'],
            'level': 'WARNING', 
            'propagate': False,
        },
        'root': {
        'handlers': ['console'],
        'level': 'DEBUG',
        },
    },
}

JAZZMIN_SETTINGS = {
    "site_title":"Welcome Session Server",
    "site_header":"Sesion Server",
    "site_brand": "Sesion Server",
    "welcome_sign": "Welcome to the Session SErver",
    "copyright": "Edart Artur Strzelczyk",
    "show_ui_builder": True,
}

CACHES = {
    'default': {
        'BACKEND': 'django_redis.cache.RedisCache',
        'LOCATION': 'redis://redis:6379/1',
        'OPTIONS': {
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
        },
        'TIMEOUT': CACHE_TIMEOUT,  
    }
}

