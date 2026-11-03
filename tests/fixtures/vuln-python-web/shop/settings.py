SECRET_KEY = "django-insecure-q8w7e6r5t4y3u2i1o9p8a7s6d5f4"
DEBUG = True
ALLOWED_HOSTS = ["*"]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
]

SESSION_COOKIE_SECURE = False
