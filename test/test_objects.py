# Copyright 2016-2018 Yubico AB
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import absolute_import, division

from yubihsm.objects import (
    ObjectInfo,
    YhsmObject,
    Opaque,
    AuthenticationKey,
    AsymmetricKey,
    WrapKey,
    HmacKey,
    Template,
    OtpAeadKey,
)
from yubihsm.core import AuthSession
from yubihsm.defs import ORIGIN, ALGORITHM, OBJECT
from binascii import a2b_hex
from mock import MagicMock
from random import randint

import unittest


_DATA = a2b_hex(
    "ffffffffffffffff00010028ffff0226000244454641554c5420415554484b4559204348414e47452054484953204153415000c0ffeec0ffee01ffffffffffffffff"  # noqa E501
)


class TestObjectInfo(unittest.TestCase):
    def test_objectinfo_parsing(self):
        info = ObjectInfo.parse(_DATA)
        self.assertEqual(info.capabilities, 0xFFFFFFFFFFFFFFFF)
        self.assertEqual(info.id, 1)
        self.assertEqual(info.size, 40)
        self.assertEqual(info.domains, 0xFFFF)
        self.assertEqual(info.object_type, OBJECT.AUTHENTICATION_KEY)
        self.assertEqual(info.algorithm, ALGORITHM.AES128_YUBICO_AUTHENTICATION)
        self.assertEqual(info.sequence, 0)
        self.assertEqual(info.origin, ORIGIN.IMPORTED)
        self.assertEqual(info.label, "DEFAULT AUTHKEY CHANGE THIS ASAP")
        self.assertEqual(info.delegated_capabilities, 0xFFFFFFFFFFFFFFFF)

    def test_non_utf8_label(self):
        label = b"\xfe\xed\xfa\xce" * 10
        data = bytearray(_DATA)
        data[18:58] = label
        info = ObjectInfo.parse(bytes(data))
        self.assertEqual(info.label, label)
        self.assertIsInstance(info.label, bytes)


class TestYhsmObject(unittest.TestCase):
    def test_get_info(self):
        AuthMock = MagicMock(AuthSession)
        AuthMock.send_secure_cmd.return_value = b"\x00\x00\x7f\xff\xff\xff\xff\xff\x00\x05\x01\x00\x00)\x05\x16\x00\x01hmaclabel\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"  # noqa E501

        # Create instance from mocked data and set the object type
        obj = YhsmObject(session=AuthMock, object_id=5)
        obj.object_type = OBJECT.HMAC_KEY

        # The expected ObjectInfo is below
        info = ObjectInfo(
            capabilities=140737488355327,
            id=5,
            size=256,
            domains=41,
            object_type=OBJECT.HMAC_KEY,
            algorithm=ALGORITHM.HMAC_SHA512,
            sequence=0,
            origin=ORIGIN.GENERATED,
            label="hmaclabel",
            delegated_capabilities=0,
        )

        self.assertEqual(info, obj.get_info())

    def test_delete(self):
        AuthMock = MagicMock(AuthSession)
        AuthMock.send_secure_cmd.return_value = b""
        obj = YhsmObject(session=AuthMock, object_id=5)
        obj.object_type = OBJECT.HMAC_KEY
        obj.delete()

    def test__create(self):
        # create for every type
        items = [
            (OBJECT.OPAQUE, Opaque),
            (OBJECT.AUTHENTICATION_KEY, AuthenticationKey),
            (OBJECT.ASYMMETRIC_KEY, AsymmetricKey),
            (OBJECT.WRAP_KEY, WrapKey),
            (OBJECT.HMAC_KEY, HmacKey),
            (OBJECT.TEMPLATE, Template),
            (OBJECT.OTP_AEAD_KEY, OtpAeadKey),
        ]

        AuthMock = MagicMock(AuthSession)

        for obj_type, obj_class in items:
            id_num = randint(1, 17)
            obj = YhsmObject._create(obj_type, AuthMock, id_num)
            self.assertIsInstance(obj, obj_class)
            self.assertEqual(obj.id, id_num)
            expected_repr = "{class_name}(id={id_num})".format(
                class_name=obj_class.__name__, id_num=id_num
            )
            self.assertEqual(obj.__repr__(), expected_repr)
