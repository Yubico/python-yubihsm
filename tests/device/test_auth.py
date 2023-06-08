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

from yubihsm.defs import COMMAND, CAPABILITY, ERROR
from yubihsm.objects import AuthenticationKey
from yubihsm.exceptions import YubiHsmAuthenticationError, YubiHsmDeviceError
from yubihsm.utils import password_to_key
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from binascii import a2b_hex
import pytest
import os


class TestAuthenticationKey:
    def test_put_unicode_authkey(self, hsm, session):
        # UTF-8 encoded unicode password
        password = b"\xF0\x9F\x98\x81\xF0\x9F\x98\x83\xF0\x9F\x98\x84".decode()

        authkey = AuthenticationKey.put_derived(
            session,
            0,
            "Test PUT authkey",
            1,
            CAPABILITY.NONE,
            CAPABILITY.NONE,
            password,
        )

        with hsm.create_session_derived(authkey.id, password) as session:
            message = os.urandom(256)
            resp = session.send_secure_cmd(COMMAND.ECHO, message)

        assert resp == message

        authkey.delete()


class TestChangeAuthenticationKey:
    @pytest.fixture(autouse=True)
    def prerequisites(self, info):
        if info.version < (2, 1, 0):
            pytest.skip("Change authentication key requires 2.1.0")

    def test_change_password(self, hsm, session):
        # Create an auth key with the capability to change
        authkey = AuthenticationKey.put_derived(
            session,
            0,
            "Test CHANGE authkey",
            1,
            CAPABILITY.CHANGE_AUTHENTICATION_KEY,
            CAPABILITY.NONE,
            "first_password",
        )

        # Can't change the password of another key
        with pytest.raises(YubiHsmDeviceError) as context:
            authkey.change_password("second_password")
        assert context.value.code == ERROR.INVALID_ID

        # Try again, using the new auth key
        with hsm.create_session_derived(authkey.id, "first_password") as session:
            authkey.with_session(session).change_password("second_password")

        with pytest.raises(YubiHsmAuthenticationError):
            hsm.create_session_derived(authkey.id, "first_password")

        hsm.create_session_derived(authkey.id, "second_password").close()

        authkey.delete()
        with pytest.raises(YubiHsmDeviceError) as context:
            hsm.create_session_derived(authkey.id, "second_password")
        assert context.value.code == ERROR.OBJECT_NOT_FOUND

    def test_change_raw_keys(self, session, hsm):
        key_enc = a2b_hex("090b47dbed595654901dee1cc655e420")
        key_mac = a2b_hex("592fd483f759e29909a04c4505d2ce0a")

        # Create an auth key with the capability to change
        authkey = AuthenticationKey.put(
            session,
            0,
            "Test CHANGE authkey",
            1,
            CAPABILITY.CHANGE_AUTHENTICATION_KEY,
            CAPABILITY.NONE,
            key_enc,
            key_mac,
        )

        with hsm.create_session_derived(authkey.id, "password") as session:
            key_enc, key_mac = password_to_key("second_password")
            authkey.with_session(session).change_key(key_enc, key_mac)

        with hsm.create_session_derived(authkey.id, "second_password"):
            pass

        authkey.delete()


class TestSessions:
    def test_parallel_sessions(self, session, hsm):
        authkey1 = AuthenticationKey.put_derived(
            session,
            0,
            "Test authkey 1",
            1,
            CAPABILITY.NONE,
            CAPABILITY.NONE,
            "one",
        )

        authkey2 = AuthenticationKey.put_derived(
            session,
            0,
            "Test authkey 2",
            2,
            CAPABILITY.NONE,
            CAPABILITY.NONE,
            "two",
        )

        authkey3 = AuthenticationKey.put_derived(
            session,
            0,
            "Test authkey 3",
            1,
            CAPABILITY.NONE,
            CAPABILITY.NONE,
            "three",
        )

        session1 = hsm.create_session_derived(authkey1.id, "one")
        session2 = hsm.create_session_derived(authkey2.id, "two")
        session3 = hsm.create_session_derived(authkey3.id, "three")

        session2.close()
        session1.send_secure_cmd(COMMAND.ECHO, b"hello")
        session3.send_secure_cmd(COMMAND.ECHO, b"hi")

        session1.send_secure_cmd(COMMAND.ECHO, b"hello")
        session3.send_secure_cmd(COMMAND.ECHO, b"greetings")
        session1.close()

        session3.send_secure_cmd(COMMAND.ECHO, b"good bye")
        session3.close()

        authkey1.delete()
        authkey2.delete()
        authkey3.delete()


class TestAymmetricAuthenticationKey:
    @pytest.fixture(autouse=True)
    def prerequisites(self, info):
        if info.version < (2, 3, 0):
            pytest.skip("Asymmetric authentication requires 2.3.0")

    def test_put_public_key(self, hsm, session):
        private_key = ec.generate_private_key(ec.SECP256R1(), backend=default_backend())

        authkey = AuthenticationKey.put_public_key(
            session,
            0,
            "Test PUT asym authkey",
            1,
            CAPABILITY.NONE,
            CAPABILITY.NONE,
            private_key.public_key(),
        )

        try:
            with hsm.create_session_asymmetric(
                authkey.id, private_key
            ) as asymmetric_session:
                message = os.urandom(256)
                resp = asymmetric_session.send_secure_cmd(COMMAND.ECHO, message)
                assert message == resp
        finally:
            authkey.delete()

    def test_change_public_key(self, hsm, session):
        first_private_key = ec.generate_private_key(
            ec.SECP256R1(), backend=default_backend()
        )
        second_private_key = ec.generate_private_key(
            ec.SECP256R1(), backend=default_backend()
        )

        authkey = AuthenticationKey.put_public_key(
            session,
            0,
            "Test PUT asym authkey",
            1,
            CAPABILITY.CHANGE_AUTHENTICATION_KEY,
            CAPABILITY.NONE,
            first_private_key.public_key(),
        )

        with hsm.create_session_asymmetric(
            authkey.id, first_private_key
        ) as asymmetric_session:
            authkey.with_session(asymmetric_session).change_public_key(
                second_private_key.public_key()
            )

        try:
            with hsm.create_session_asymmetric(
                authkey.id, second_private_key
            ) as asymmetric_session:
                message = os.urandom(256)
                resp = asymmetric_session.send_secure_cmd(COMMAND.ECHO, message)
                assert message == resp
        finally:
            authkey.delete()
