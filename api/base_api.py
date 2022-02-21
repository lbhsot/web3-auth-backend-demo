import json
from functools import wraps
from http.client import HTTPException, METHOD_NOT_ALLOWED

from django.http.response import HttpResponse

from api.models import LoginRecord
from api.utils import get_client_ip


def require_method(methods):
    def wrapper(fn):
        @wraps(fn)
        def inner(request, *args, **kwargs):
            if request.method not in methods:
                raise HTTPException(METHOD_NOT_ALLOWED)
            return fn(request, *args, **kwargs)

        inner.__annotations__.update(dict(zip(methods, [[]] * len(methods))))

        return inner

    return wrapper


def login_required(fn):
    @wraps(fn)
    def inner(request, *args, **kwargs):
        message: str = request.headers.get('cobo-siwe-message', '')
        signature: str = request.headers.get('cobo-siwe-signature', '')
        unauthorized_resp = HttpResponse('Unauthorized', status=401)
        # check header
        if not message or not signature:
            return unauthorized_resp
        # remote ip check; message and signature check; expiration check;
        remote_ip = get_client_ip(request)
        record = LoginRecord.objects.filter(
            remote_ip=remote_ip,
            message=json.loads(message),
            signature=signature,
        ).first()
        if not record:
            return unauthorized_resp
        try:
            record.validate()
        except:
            return unauthorized_resp
        return fn(request, *args, **kwargs)

    return inner
