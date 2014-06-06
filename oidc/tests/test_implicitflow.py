# -*- coding: utf-8 -*-

from oidc.implicitflow import (
    is_access_token_required,
    IDToken,
    Request,
    Response,
)


def test_is_access_token_required():
    # response_type = token id_token
    reqdict = {
        'client_id': 'client_id',
        'response_type': 'token id_token',
        'redirect_uri': 'https://example.com/cb',
        'nonce': 'nonce',
    }
    request = Request()
    request.update(reqdict)

    respdict = {
        'access_token': 'access_token',
        'token_type': 'bearer',
        'id_token': IDToken(),
    }
    response = Response(request)
    response.update(respdict)
    assert is_access_token_required(response) is True

    # response_type = id_token
    reqdict['response_type'] = 'id_token'
    request = Request()
    request.update(reqdict)

    del respdict['access_token']
    response = Response(request)
    response.update(respdict)
    assert is_access_token_required(response) is False
