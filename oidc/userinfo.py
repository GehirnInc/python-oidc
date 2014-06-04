# -*- coding: utf-8 -*-

from py3oauth2.message import (
    Message,
    Parameter,
)


class UserInfo(Message):
    __scopes__ = {
        'openid': {'sub'},
        'profile': {'name', 'given_name', 'family_name', 'middle_name',
                    'nickname', 'preferred_username', 'profile', 'picture',
                    'website', 'gender', 'birthdate', 'zoneinfo', 'locale',
                    'update_at'},
        'email': {'email', 'email_verified'},
        'address': {'address'},
        'phone': {'phone_number', 'phone_number_verified'},
    }
    sub = Parameter(str, required=True)

    # scope = profile
    name = Parameter(str)
    given_name = Parameter(str)
    family_name = Parameter(str)
    middle_name = Parameter(str)
    nickname = Parameter(str)
    preferred_username = Parameter(str)
    profile = Parameter(str)
    picture = Parameter(str)
    website = Parameter(str)
    gender = Parameter(str)
    birthdate = Parameter(str)
    zoneinfo = Parameter(str)
    locale = Parameter(str)
    update_at = Parameter(int)

    # email
    email = Parameter(str)
    email_verified = Parameter(bool)

    # address
    address = Parameter(dict)

    # phone
    phone_number = Parameter(str)
    phone_number_verified = Parameter(bool)

    def filter(self, scopes):
        inst = self.__class__()

        params = set()
        for scope in scopes:
            params.update(self.__scopes__[scope])

        for param in params:
            setattr(inst, param, getattr(self, param))

        return inst
