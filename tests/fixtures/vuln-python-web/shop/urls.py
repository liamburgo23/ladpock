from django.urls import include, path
from rest_framework.routers import DefaultRouter

from . import views

router = DefaultRouter()
router.register(r"invoices", views.InvoiceViewSet)

urlpatterns = [
    path("profile/update/", views.update_profile),
    path("invoices/<int:pk>/", views.invoice_detail),
    path("api/", include(router.urls)),
]
