from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.utils.safestring import mark_safe
from django.views.decorators.csrf import csrf_exempt
from rest_framework import serializers, viewsets

from .models import Invoice, Profile


@csrf_exempt
def update_profile(request):
    if request.method == "POST":
        Profile.objects.filter(id=request.POST["id"]).update(bio=request.POST["bio"])
    return JsonResponse({"ok": True})


@login_required
def invoice_detail(request, pk):
    invoice = Invoice.objects.get(pk=pk)
    return JsonResponse({"html": mark_safe(invoice.notes)})


class InvoiceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Invoice
        fields = "__all__"


class InvoiceViewSet(viewsets.ModelViewSet):
    queryset = Invoice.objects.all()
    serializer_class = InvoiceSerializer
