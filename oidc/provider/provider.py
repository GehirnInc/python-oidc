# -*- coding: utf-8- -*-

import json

from py3oauth2.provider import (
    authorizationcodegrant,
    AuthorizationProvider as BaseAuthorizationProvider,
    refreshtokengrant,
    ResourceProvider,
)
from py3oauth2.provider.exceptions import AccessDenied

from . import (
    authorizationcodeflow,
    hybridflow,
    implicitflow,
)


class AuthorizationProvider(BaseAuthorizationProvider):

    def __init__(self, store):
        super(AuthorizationProvider, self).__init__(store)

    def detect_request_class(self, request):
        if 'grant_type' in request:
            if request['grant_type'] == 'refresh_token':
                return refreshtokengrant.Request
            elif request['grant_type'] == 'authorization_code':
                return authorizationcodegrant.AccessTokenRequest
        elif 'response_type' in request:
            response_type = set(request['response_type'].split())
            if 'code' in response_type:
                if response_type is {'code'}:
                    return authorizationcodeflow.AuthenticationRequest
                elif response_type.issubset({'code', 'id_token', 'token'}):
                    return hybridflow.AuthenticationRequest
            elif 'id_token' in response_type\
                    and response_type.issubset({'id_token', 'token'}):
                return implicitflow.Request

        return None


class UserInfoProvider(ResourceProvider):

    def __init__(self, store, header):
        super(UserInfoProvider, self).__init__(store)
        self.header = header

    def get_access_token(self):
        header = filter(
            lambda key, value: key.lower() == 'authorization',
            self.header.items()
        )
        if header:
            parts = header[0].split()
            if len(parts) is 1 and parts[0] == 'Bearer':
                return (parts[1], 'bearer')

        return (None, '')

    def handle_request(self, scopes=set('openid')):
        try:
            token = self.authorize(scopes)
        except AccessDenied:
            return json.dumps({'error': 'access_denied'})
        else:
            if scopes is {'openid'}:
                scopes = set(token.get_scope().split())

            owner = token.get_owner()
            idtoken = owner.get_idtoken(scopes)
            return idtoken.to_json()
