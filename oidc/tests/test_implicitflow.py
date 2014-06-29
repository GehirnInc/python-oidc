# -*- coding: utf-8 -*-

import json

from jwt.jwt import JWT

from oidc.implicitflow import (
    is_access_token_required,
    Request,
    Response,
)
from oidc.tests import (
    mock,
    TestBase,
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
        'id_token': 'dummy.id.token',
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


class RequestTest(TestBase):

    @property
    def target(self):
        from oidc.implicitflow import Request
        return Request

    def test_answer(self):
        inst = self.target()
        inst.update({
            'client_id': self.client.id,
            'redirect_uri': self.client.get_redirect_uri(),
            'response_type': 'id_token',
            'scope': 'openid profile',
            'nonce': 'noncestring',
            'state': 'statestring',
        })
        inst.validate()

        resp = inst.answer(self.provider, self.owner)
        resp.validate()

        self.assertEqual(resp.state, 'statestring')

        jwt = JWT(self.jwkset.copy())
        self.assertTrue(jwt.verify(resp.id_token))

        id_token = json.loads(jwt.decode(resp.id_token).decode('utf8'))
        self.assertEqual(id_token['nonce'], 'noncestring')

    def test_answer_with_token(self):
        inst = self.target()
        inst.update({
            'client_id': self.client.id,
            'redirect_uri': self.client.get_redirect_uri(),
            'response_type': 'id_token token',
            'scope': 'openid profile',
            'nonce': 'noncestring',
            'state': 'statestring',
        })
        inst.validate()

        resp = inst.answer(self.provider, self.owner)
        resp.validate()

        token = self.store.get_access_token(resp.access_token)
        self.assertEqual(resp.token_type, token.get_type())
        self.assertEqual(resp.scope, ' '.join(token.get_scope()))
        self.assertEqual(resp.expires_in, token.get_expires_in())

        self.assertEqual(resp.state, 'statestring')

        jwt = JWT(self.jwkset.copy())
        self.assertTrue(jwt.verify(resp.id_token))

        id_token = json.loads(jwt.decode(resp.id_token).decode('utf8'))
        self.assertEqual(id_token['nonce'], 'noncestring')
        self.assertEqual(id_token['at_hash'],
                         self.provider.left_hash(self.client.get_jws_alg(),
                                                 resp.access_token))

    def test_answer_unknown_client(self):
        from oidc.errors import UnauthorizedClient

        inst = self.target()
        inst.update({
            'client_id': 'unknown_client',
            'redirect_uri': self.client.get_redirect_uri(),
            'response_type': 'id_token',
            'scope': 'openid profile',
            'nonce': 'noncestring',
            'state': 'statestring',
        })
        inst.validate()

        try:
            inst.answer(self.provider, self.owner)
        except UnauthorizedClient as why:
            self.assertIs(why.request, inst)
            self.assertIsNone(why.redirect_uri)
        else:
            self.fail()

    def test_answer_invalid_redirect_uri(self):
        from oidc.errors import UnauthorizedClient

        inst = self.target()
        inst.update({
            'client_id': self.client.id,
            'redirect_uri': self.client.get_redirect_uri(),
            'response_type': 'id_token',
            'scope': 'openid profile',
            'nonce': 'noncestring',
            'state': 'statestring',
        })
        inst.validate()

        try:
            with mock.patch.object(self.provider, 'validate_redirect_uri',
                                   return_value=False):
                inst.answer(self.provider, self.owner)
        except UnauthorizedClient as why:
            self.assertIs(why.request, inst)
            self.assertIsNone(why.redirect_uri)
        else:
            self.fail()

    def test_answer_server_error(self):
        from oidc.errors import ServerError

        inst = self.target()
        inst.update({
            'client_id': self.client.id,
            'redirect_uri': self.client.get_redirect_uri(),
            'response_type': 'id_token token',
            'scope': 'openid profile',
            'nonce': 'noncestring',
            'state': 'statestring',
        })
        inst.validate()

        try:
            with mock.patch.object(self.store, 'issue_access_token',
                                   side_effect=ServerError):
                inst.answer(self.provider, self.owner)
        except ServerError as why:
            self.assertIs(why.request, inst)
            self.assertEqual(why.redirect_uri, self.client.get_redirect_uri())
        else:
            self.fail()
