# -*- coding: utf-8 -*-

from py3oauth2.authorizationcodegrant import (
    AuthorizationRequest,
    AuthorizationResponse,
)
from py3oauth2.message import Parameter

from ..idtoken import IDToken as BaseIDToken

__all__ = ['IDToken', 'AuthenticationResponse', 'AuthenticationRequest']


class IDToken(BaseIDToken):
    at_hash = Parameter(str)


class AuthenticationResponse(AuthorizationResponse):
    __id_token_class__ = IDToken

    # OpenID Connect parameters
    id_token = Parameter(str, required=True)


class AuthenticationRequest(AuthorizationRequest):
    response = AuthenticationResponse

    # OAuth2 parameters
    redirect_uri = Parameter(str, required=True)
    response_mode = Parameter(str)

    # OpenID Connect parameters
    nonce = Parameter(str, recommended=True)
    display = Parameter(str)
    prompt = Parameter(str)
    max_age = Parameter(int)
    ui_locales = Parameter(str)
    id_token_hint = Parameter(str)
    login_hint = Parameter(str)
    acr_values = Parameter(str)
