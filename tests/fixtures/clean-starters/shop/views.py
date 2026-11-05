from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.shortcuts import get_object_or_404

from .models import Order


@login_required
def order_list(request):
    orders = Order.objects.filter(user=request.user)[:50]
    return JsonResponse({"orders": [o.summary() for o in orders]})


@login_required
def order_detail(request, pk):
    order = get_object_or_404(Order, pk=pk, user=request.user)
    return JsonResponse(order.summary())
