# -*- coding: utf-8 -*-

from py3oauth2.provider.message import (
    Message,
    Parameter,
)

__all__ = ['IDToken']


def is_auth_time_required(idtoken):
    # TODO: implement this
    return False


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

    @classmethod
    def issue(cls, provider, owner, client):
        iat = datetime.utcnow()
        inst = cls.from_dict({
            'iss': provider.get_iss(),
            'sub': owner.get_sub(),
            'aud': ListOrString.deserialize(client.get_id()),
            'exp': self.unix_time(iat, provider.get_id_token_lifetime()),
            'iat': self.unix_time(iat),
        })
        return inst

    @staticmethod
    def unix_time(now, delta=0):
        if isinstance(delta, int):
            delta = timedelta(seconds=delta)

        return int(time.mktime((now + delta).timetuple()))
