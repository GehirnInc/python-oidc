# -*- coding: utf-8 -*-

from py3oauth2.message import Parameter

from oidc.authorizationcodeflow import AuthenticationRequest
from oidc.errors import ErrorException
from oidc.idtoken import IDToken
from oidc.implicitflow import Response


def is_access_token_required(resp):
    return 'token' in resp.request.response_type.split()


def is_at_hash_required(idtoken):
    return is_access_token_required(idtoken.response)


def is_id_token_required(resp):
    return 'id_token' in resp.request.response_type.split()


class IDToken(IDToken):
    nonce = Parameter(str, required=True)
    at_hash = Parameter(str, required=is_at_hash_required)
    c_hash = Parameter(str, required=True)


class AuthenticationResponse(Response):

    # OAuth2.0 parameters
    access_token = Parameter(str, required=is_access_token_required)
    token_type = Parameter(str, required=is_access_token_required)
    code = Parameter(str, required=True)

    # OpenID Connect parameters
    id_token = Parameter(str, required=is_id_token_required)


class AuthenticationRequest(AuthenticationRequest):
    response = AuthenticationResponse
    id_token = IDToken

    def answer(self, provider, owner):
        response = super(AuthenticationRequest, self).answer(provider, owner)
        response_types = set(self.response_type.split())
        client = provider.store.get_client(self.client_id)

        if 'token' in response_types:
            try:
                token = provider.store.issue_access_token(
                    client, owner, provider.normalize_scope(self.scope))
            except ErrorException as why:
                why.request = self
                why.redirect_uri = self.redirect_uri
                raise

            response.update({
                'access_token': token.get_token(),
                'token_type': token.get_type(),
                'scope': ' '.join(token.get_scope()),
                'expires_in': token.get_expires_in(),
            })

        if 'id_token' in response_types:
            id_token = self.id_token(response,
                                     provider.get_iss(),
                                     owner.get_sub(),
                                     client.get_id(),
                                     provider.get_id_token_lifetime())
            id_token.update({
                'nonce': self.nonce,
                'c_hash': provider.left_hash(client.get_jws_alg(),
                                             response.code)
            })

            if 'token' in response_types:
                id_token.at_hash = provider.left_hash(client.get_jws_alg(),
                                                      response.access_token)

            response.id_token = provider.encode_token(id_token, client)

        return response
