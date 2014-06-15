# -*- coding: utf-8 -*-

import time
from datetime import datetime

from py3oauth2.message import (
    Message,
    Parameter,
)

__all__ = ['IDToken']


def is_auth_time_required(idtoken):
    request = idtoken.response.request
    return hasattr(request, 'max_age') and request.max_age


class ListOrString(list):

    def serialize(self):
        if len(self) is 1:
            return self[0]
        return self

    @classmethod
    def deserialize(cls, value):
        if isinstance(value, list):
            inst = cls()
            inst.extend(value)
            return inst
        elif isinstance(value, str):
            inst = cls()
            inst.append(value)
            return inst


class IDToken(Message):
    iss = Parameter(str, required=True)
    sub = Parameter(str, required=True)
    aud = Parameter(ListOrString, required=True)
    exp = Parameter(int, required=True)
    iat = Parameter(int, required=True)
    auth_time = Parameter(int)
    nonce = Parameter(str)
    acr = Parameter(str)
    amr = Parameter(str)
    azp = Parameter(str)

    def __init__(self, response, iss, sub, client_id, lifetime):
        self.response = response

        iat = int(time.mktime(datetime.now().timetuple()))
        self.update({
            'iss': iss,
            'sub': sub,
            'aud': ListOrString.deserialize(client_id),
            'exp': iat + lifetime,
            'iat': iat,
        })
