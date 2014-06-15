# -*- coding: utf-8 -*-

import json

from jwt.jwt import JWT

from oidc.tests import (
    mock,
    TestBase,
)


class AuthenticationRequestTest(TestBase):

    @property
    def target(self):
        from oidc.hybridflow import AuthenticationRequest
        return AuthenticationRequest

    def test_answer_with_token(self):
        inst = self.target()
        inst.update({
            'client_id': self.client.id,
            'redirect_uri': self.client.get_redirect_uri(),
            'response_type': 'code token',
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

    def test_answer_with_idtoken(self):
        inst = self.target()
        inst.update({
            'client_id': self.client.id,
            'redirect_uri': self.client.get_redirect_uri(),
            'response_type': 'code id_token',
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
        self.assertEqual(id_token['c_hash'],
                         self.provider.left_hash(self.client.get_jws_alg(),
                                                 resp.code))

    def test_answer_with_token_and_idtoken(self):
        inst = self.target()
        inst.update({
            'client_id': self.client.id,
            'redirect_uri': self.client.get_redirect_uri(),
            'response_type': 'code token id_token',
            'scope': 'openid profile',
            'nonce': 'noncestring',
            'state': 'statestring',
        })
        inst.validate()

        resp = inst.answer(self.provider, self.owner)
        resp.validate()

        self.assertEqual(resp.state, 'statestring')

        token = self.store.get_access_token(resp.access_token)
        self.assertEqual(resp.token_type, token.get_type())
        self.assertEqual(resp.scope, ' '.join(token.get_scope()))
        self.assertEqual(resp.expires_in, token.get_expires_in())

        jwt = JWT(self.jwkset.copy())
        self.assertTrue(jwt.verify(resp.id_token))

        id_token = json.loads(jwt.decode(resp.id_token).decode('utf8'))
        self.assertEqual(id_token['nonce'], 'noncestring')
        self.assertEqual(id_token['c_hash'],
                         self.provider.left_hash(self.client.get_jws_alg(),
                                                 resp.code))
        self.assertEqual(id_token['at_hash'],
                         self.provider.left_hash(self.client.get_jws_alg(),
                                                 token.get_token()))

    def test_answer_server_error(self):
        from oidc.errors import ServerError

        inst = self.target()
        inst.update({
            'client_id': self.client.id,
            'redirect_uri': self.client.get_redirect_uri(),
            'response_type': 'code token',
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
