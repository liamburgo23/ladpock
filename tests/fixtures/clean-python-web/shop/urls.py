from django.urls import include, path
from rest_framework.routers import DefaultRouter

from . import views

router = DefaultRouter()
router.register(r"invoices", views.InvoiceViewSet, basename="invoice")

urlpatterns = [
    path("invoices/<int:pk>/", views.invoice_detail),
    path("api/", include(router.urls)),
]
