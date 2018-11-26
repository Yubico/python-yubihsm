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

from .utils import YubiHsmTestCase
from yubihsm.defs import COMMAND, CAPABILITY, OBJECT, ERROR
from yubihsm.objects import AuthenticationKey
from yubihsm.exceptions import YubiHsmAuthenticationError, YubiHsmDeviceError
from yubihsm.utils import password_to_key
from binascii import a2b_hex
import os


class TestAuthenticationKey(YubiHsmTestCase):

    def test_put_unicode_authkey(self):
        # UTF-8 encoded unicode password
        password = b'\xF0\x9F\x98\x81\xF0\x9F\x98\x83\xF0\x9F\x98\x84' \
            .decode('utf8')

        authkey = AuthenticationKey.put_derived(
            self.session,
            0,
            'Test PUT authkey',
            1,
            CAPABILITY.NONE,
            CAPABILITY.NONE,
            password
        )

        session = self.hsm.create_session_derived(authkey.id, password)

        message = os.urandom(256)

        resp = session.send_secure_cmd(COMMAND.ECHO, message)

        self.assertEqual(resp, message)

        authkey.delete()
        session.close()

    def test_change_password(self):
        self.require_version((2, 1, 0), 'Change authentication key')

        # Create an auth key with the capability to change
        authkey = AuthenticationKey.put_derived(
            self.session,
            0,
            'Test CHANGE authkey',
            1,
            CAPABILITY.CHANGE_AUTHENTICATION_KEY,
            CAPABILITY.NONE,
            'first_password'
        )

        # Can't change the password of another key
        with self.assertRaises(YubiHsmDeviceError) as context:
            authkey.change_password('second_password')
        self.assertEqual(context.exception.code, ERROR.INVALID_ID)

        # Try again, using the new auth key
        session = self.hsm.create_session_derived(authkey.id, 'first_password')
        authkey2 = session.get_object(authkey.id, OBJECT.AUTHENTICATION_KEY)
        authkey2.change_password('second_password')
        session.close()

        with self.assertRaises(YubiHsmAuthenticationError):
            self.hsm.create_session_derived(authkey.id, 'first_password')

        self.hsm.create_session_derived(authkey.id, 'second_password').close()

        authkey.delete()
        with self.assertRaises(YubiHsmDeviceError) as context:
            self.hsm.create_session_derived(authkey.id, 'second_password')
        self.assertEqual(context.exception.code, ERROR.OBJECT_NOT_FOUND)

    def test_change_raw_keys(self):
        self.require_version((2, 1, 0), 'Change authentication key')

        key_enc = a2b_hex('090b47dbed595654901dee1cc655e420')
        key_mac = a2b_hex('592fd483f759e29909a04c4505d2ce0a')

        # Create an auth key with the capability to change
        authkey = AuthenticationKey.put(
            self.session,
            0,
            'Test CHANGE authkey',
            1,
            CAPABILITY.CHANGE_AUTHENTICATION_KEY,
            CAPABILITY.NONE,
            key_enc,
            key_mac
        )

        session = self.hsm.create_session_derived(authkey.id, 'password')
        authkey2 = session.get_object(authkey.id, OBJECT.AUTHENTICATION_KEY)

        key_enc, key_mac = password_to_key('second_password')

        authkey2.change_key(key_enc, key_mac)
        session.close()

        self.hsm.create_session_derived(authkey.id, 'second_password').close()

        authkey.delete()
