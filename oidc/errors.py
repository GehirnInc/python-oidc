# -*- coding: utf-8 -*-

from py3oauth2.errors import (
    make_error,
    AccessDenied,
    ErrorException,
    InvalidRequest,
    InvalidScope,
    ServerError,
    UnauthorizedClient,
    UnsupportedGrantType,
    UnsupportedResponseType,
)


__all__ = [
    'AccessDenied', 'ErrorException', 'InvalidRequest', 'InvalidScope',
    'InvalidScope', 'ServerError', 'UnauthorizedClient',
    'UnsupportedGrantType', 'UnsupportedResponseType', 'InteractionRequired',
    'LoginRequired'
]


InteractionRequired = make_error('InteractionRequired', 'interaction_required')
LoginRequired = make_error('LoginRequired', 'login_required')
