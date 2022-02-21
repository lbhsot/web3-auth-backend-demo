from datetime import datetime

from dateutil.parser import isoparse
from dateutil.tz import UTC
from django.db import models
from siwe.siwe import SiweMessage, ExpiredMessage


class Wallet(models.Model):
    address = models.CharField(null=False, unique=True, max_length=200)
    disabled_at = models.DateTimeField(default=None, null=True)


class LoginRecord(models.Model):
    remote_ip = models.CharField(max_length=200)
    address = models.CharField(null=False, max_length=200)
    message = models.TextField(null=False)
    signature = models.TextField(null=False)

    def validate(self):
        message = SiweMessage(self.message)
        if message.expiration_time and not message.expiration_time_parsed:
            message.expiration_time_parsed = isoparse(message.expiration_time)
        if message.not_before and not message.not_before_parsed:
            message.not_before_parsed = isoparse(message.not_before)
        message.validate(self.signature)
        if (
            message.not_before_parsed
            and datetime.now(UTC) < message.not_before_parsed
        ):
            raise ExpiredMessage
        # check nonce
        datetime.fromtimestamp(int(message.nonce) / 1000)

