# -*- coding: utf-8 -*-

from py3oauth2.provider.implicitgrant import (
    Request as BaseRequest,
    Response as BaseResponse,
)
from py3oauth2.provider.message import Parameter

from ..idtoken import IDToken as BaseIDToken

__all__ = ['IDToken', 'Request', 'Response']


def is_access_token_required(resp):
    return resp.request.response_type != 'id_token'


class IDToken(BaseIDToken):
    nonce = Parameter(str, required=True)
    at_hash = Parameter(str)


class Response(BaseResponse):
    __id_token_class__ = IDToken

    # OAuth2 parameters
    access_token = Parameter(str, required=is_access_token_required)
    # NOTES: needs `scope`?

    # OpenID Connect parameters
    id_token = Parameter(IDToken, required=True)


class Request(BaseRequest):
    response = Response

    # OAuth2 parameters
    response_type = Parameter(str, required=True)  # id_token token or id_token
    redirect_uri = Parameter(str, required=True)

    # OpenID Connect parameters
    nonce = Parameter(str, required=True)
