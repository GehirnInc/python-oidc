# -*- coding: utf-8 -*-

from py3oauth2.provider.message import (
    Message,
    Parameter,
)

__all__ = ['IDToken']


def is_auth_time_required(idtoken):
    # TODO: implement this
    return False


def is_nonce_required(idtoken):
    # TODO: implement here
    return False


class IDToken(Message):
    iss = Parameter(str, required=True)
    sub = Parameter(str, required=True)
    aud = Parameter(str, required=True)
    exp = Parameter(int, required=True)
    iat = Parameter(int, required=True)
    auth_time = Parameter(int, required=is_auth_time_required)
    nonce = Parameter(str, required=is_nonce_required)
    acr = Parameter(str)
    amr = Parameter(str)
    azp = Parameter(str)
