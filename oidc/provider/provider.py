# -*- coding: utf-8- -*-

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

    def __init__(self, store, iss):
        super(AuthorizationProvider, self).__init__(store)
        self.iss = iss

    def get_iss(self):
        return self.iss

    def detect_request_class(self, request):
        if 'grant_type' in request:
            if request['grant_type'] == 'refresh_token':
                return refreshtokengrant.Request
            elif request['grant_type'] == 'authorization_code':
                return authorizationcodegrant.AccessTokenRequest
        elif 'response_type' in request:
            response_type = set(request['response_type'].split())
            if 'code' in response_type:
                if response_type == {'code'}:
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
