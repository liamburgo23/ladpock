from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from rest_framework import permissions, serializers, viewsets

from .models import Invoice


@login_required
def invoice_detail(request, pk):
    invoice = get_object_or_404(Invoice, pk=pk, owner=request.user)
    return JsonResponse({"number": invoice.number})


class InvoiceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Invoice
        fields = ["id", "number", "total"]


class InvoiceViewSet(viewsets.ModelViewSet):
    serializer_class = InvoiceSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return Invoice.objects.filter(owner=self.request.user)
