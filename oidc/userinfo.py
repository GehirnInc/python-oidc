# -*- coding: utf-8 -*-

from py3oauth2.provider.message import (
    Message,
    Parameter,
)


class UserInfo(Message):
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
