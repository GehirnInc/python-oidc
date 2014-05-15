# -*- coding: utf-8- -*-

from py3oauth2.provider import (
    AuthorizationProvider as BaseAuthorizationProvider,
    ResourceProvider,
)
from py3oauth2.provider.exceptions import AccessDenied

from . import (
    authorizationcodeflow,
    hybridflow,
    implicitflow,
)


class AuthorizationProvider(BaseAuthorizationProvider):

    def __init__(self, store, iss, jwt):
        super(AuthorizationProvider, self).__init__(store)

        self.iss = iss
        self.jwt = jwt

        self.add_authorization_handler(
            ('code', ), authorizationcodeflow.AuthenticationRequest)

        self.add_authorization_handler(
            ('code', 'token'), hybridflow.AuthenticationRequest)
        self.add_authorization_handler(
            ('code', 'id_token'), hybridflow.AuthenticationRequest)
        self.add_authorization_handler(
            ('code', 'id_token', 'token'), hybridflow.AuthenticationRequest)

        self.add_authorization_handler(
            ('id_token', ), implicitflow.Request)
        self.add_authorization_handler(
            ('id_token', 'token'), implicitflow.Request)

    def get_iss(self):
        return self.iss

    def handle_request(self, request, owner,
                       sign_jwt=True, sign_alg='HS256', sign_kid=None,
                       encrypt_jwt=False, encrypt_alg='RSA1_5',
                       encrypt_enc='A128CBC-HS256', encrypt_kid=None):

        response = super().handle_request(request, owner)
        if hasattr(response, 'id_token') and response.id_token:
            response.id_token.bind(
                self.jwt, sign_jwt, sign_alg, sign_kid,
                encrypt_jwt, encrypt_alg, encrypt_enc, encrypt_kid
            )

        return response


class UserInfoProvider(ResourceProvider):

    def __init__(self, store, header):
        super(UserInfoProvider, self).__init__(store)
        self.header = header

    def get_access_token(self):
        header = list(filter(
            lambda item: item[0].lower() == 'authorization',
            self.header.items()
        ))
        if header:
            key, value = header[0]
            parts = value.split()
            if len(parts) is 2 and parts[0] == 'Bearer':
                return (parts[1], 'bearer')

        return (None, '')

    def handle_request(self, scopes=set(['openid'])):
        try:
            token = self.authorize(scopes)
        except AccessDenied:
            raise  # TODO: return error response
        else:
            if scopes == {'openid'}:
                scopes = set(token.get_scope().split())

            owner = token.get_owner()
            user_info = owner.get_user_info(scopes)
            return user_info
