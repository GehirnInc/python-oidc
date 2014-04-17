# -*- coding: utf-8 -*-

from py3oauth2.provider.message import Parameter

from ..idtoken import IDToken as BaseIDToken
from .authorizationcodeflow import (
    AuthenticationRequest as BaseAuthenticationRequest,
)
from .implicitflow import (
    Response as BaseAuthenticationResponse,
)


def is_at_hash_required(idtoken):
    # TODO: implement this
    return False


def is_chash_required(idtoken):
    # TODO: implement this
    return False


def is_access_token_required(resp):
    # TODO: implement this
    return False


def id_token_required(resp):
    # TODO: implement this
    return False


class IDToken(BaseIDToken):
    nonce = Parameter(str, required=True)
    at_hash = Parameter(str, required=is_at_hash_required)
    c_hash = Parameter(str, required=is_chash_required)


class AuthenticationResponse(BaseAuthenticationResponse):
    __id_token_class__ = IDToken

    # OAuth2.0 parameters
    access_token = Parameter(str, required=is_access_token_required)
    code = Parameter(str, required=True)

    id_token = Parameter(str, required=id_token_required)


class AuthenticationRequest(BaseAuthenticationRequest):
    response = AuthenticationResponse

    # OAuth2.0 parameters
    response_type = Parameter(str, required=True)
