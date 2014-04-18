# -*- coding: utf-8 -*-

from py3oauth2.provider.implicitgrant import (
    Request as BaseRequest,
    Response as BaseResponse,
)
from py3oauth2.provider import message

from ..idtoken import IDToken as BaseIDToken

__all__ = ['IDToken', 'Request', 'Response']


def is_access_token_required(resp):
    return resp.request.response_type != 'id_token'


class IDToken(BaseIDToken):
    nonce = message.Parameter(str, required=True)
    at_hash = message.Parameter(str)


class Response(BaseResponse):
    __id_token_class__ = IDToken

    # OAuth2 parameters
    access_token = message.Parameter(str, required=is_access_token_required)
    token_type = message.Parameter(str, required=is_access_token_required)
    # NOTES: needs `scope`?

    # OpenID Connect parameters
    id_token = message.Parameter(__id_token_class__, required=True)


class Request(BaseRequest):
    response = Response

    # OAuth2 parameters
    response_type = message.Parameter(str, required=True)
    redirect_uri = message.Parameter(str, required=True)

    # OpenID Connect parameters
    nonce = message.Parameter(str, required=True)

    def answer(self, provider, owner):
        try:
            try:
                client = provider.store.get_client(self.client_id)
                if client is None or not provider.authorize_client(client):
                    raise message.UnauthorizedClient()

                id_token = self.response.__id_token_class__.issue(
                    provider, owner, client
                )
                id_token.nonce = self.nonce
                id_token.validate()

                response = self.response.from_dict(self, {
                    'id_token': id_token,
                    'state': self.state,
                })

                if self.response_type != 'id_token':
                    token = provider.store.persist_access_token(
                        client, owner, provider.generate_access_token(),
                        self.scope, None
                    )
                    response.access_token = token.get_token()
                    response.token_type = token.get_type()
                    response.scope = token.get_scope()
                    response.expires_in = token.get_expires_in()
            except message.RequestError:
                raise
            except:
                raise message.ServerError()
        except message.ServerError() as why:
            resp = self.err_response(self)
            resp.error = why.kind
            resp.state = self.state
            return resp
        else:
            return response
