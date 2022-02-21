import json

from django.http import HttpResponse, JsonResponse
from siwe.siwe import SiweMessage

from api.base_api import require_method, login_required
from api.models import LoginRecord, Wallet
from api.utils import get_client_ip


def index(request):
    return HttpResponse("Hello, world. You're at the polls index.")


@require_method(['POST'])
def verify(request):
    payload = json.loads(request.body.decode("utf-8"))
    message = payload.get('message')
    signature = payload.get('signature')
    siwe_message = SiweMessage(message)
    # check account
    wallet = Wallet.objects.filter(address=siwe_message.address).first()
    if not wallet:
        Wallet.objects.create(address=siwe_message.address)
    else:
        if wallet.disabled_at:
            return HttpResponse('Inactive user, Authentication attempt rejected.', status=403)
    # check replay attack
    if LoginRecord.objects.filter(
        message=message,
        signature=signature,
    ).exists():
        return HttpResponse('Used nonce, Authentication attempt rejected.', status=403)
    # validate message and signature
    record = LoginRecord(
        remote_ip=get_client_ip(request),
        address=siwe_message.address,
        message=message,
        signature=signature,
    )
    try:
        record.validate()
    except:
        return HttpResponse('Authentication attempt rejected.', status=400)
    record.save()
    return JsonResponse(dict(success=True))


@require_method(['GET'])
@login_required
def test(request):
    return JsonResponse(dict(success=True))
