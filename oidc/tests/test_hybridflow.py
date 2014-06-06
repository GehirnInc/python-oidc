# -*- coding: utf-8 -*-

from oidc.hybridflow import (
    AuthenticationRequest,
    AuthenticationResponse,
    IDToken,
    is_access_token_required,
    is_id_token_required,
)


def test_response_validators_code():
    # response_type = code
    reqdict = {
        'client_id': 'client_id',
        'response_type': 'code',
        'redirect_uri': 'https://example.com/cb',
    }
    request = AuthenticationRequest()
    request.update(reqdict)

    respdict = {
        'code': 'code',
    }
    response = AuthenticationResponse(request)
    response.update(respdict)
    assert is_access_token_required(response) is False
    assert is_id_token_required(response) is False


def test_response_validators_code_id_token():
    # response_type = code id_token
    reqdict = {
        'client_id': 'client_id',
        'response_type': 'code id_token',
        'redirect_uri': 'https://example.com/cb',
    }
    request = AuthenticationRequest()
    request.update(reqdict)

    respdict = {
        'code': 'code',
        'id_token': IDToken(),
    }
    response = AuthenticationResponse(request)
    response.update(respdict)
    assert is_access_token_required(response) is False
    assert is_id_token_required(response) is True


def test_response_validators_code_token():
    # response_type = code token
    reqdict = {
        'client_id': 'client_id',
        'response_type': 'code token',
        'redirect_uri': 'https://example.com/cb',
    }
    request = AuthenticationRequest()
    request.update(reqdict)

    respdict = {
        'code': 'code',
        'token': 'access_token',
    }
    response = AuthenticationResponse(request)
    response.update(respdict)
    assert is_access_token_required(response) is True
    assert is_id_token_required(response) is False


def test_response_validators_code_id_token_token():
    # response_type = code id_token token
    reqdict = {
        'client_id': 'client_id',
        'response_type': 'code id_token token',
        'redirect_uri': 'https://example.com/cb',
    }
    request = AuthenticationRequest()
    request.update(reqdict)

    respdict = {
        'code': 'code',
        'id_token': IDToken(),
        'access_token': 'access_token',
        'token_type': 'bearer',
    }
    response = AuthenticationResponse(request)
    response.update(respdict)
    assert is_access_token_required(response) is True
    assert is_id_token_required(response) is True
