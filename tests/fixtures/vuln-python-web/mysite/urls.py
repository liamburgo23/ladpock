from django.urls import include, path

urlpatterns = [
    path("shop/", include("shop.urls")),
]
