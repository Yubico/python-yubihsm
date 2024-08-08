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

from yubihsm.core import MAX_MSG_SIZE
from yubihsm.defs import ALGORITHM, CAPABILITY, OBJECT, COMMAND, ORIGIN, FipsStatus
from yubihsm.objects import (
    YhsmObject,
    AsymmetricKey,
    HmacKey,
    WrapKey,
    AuthenticationKey,
)
from cryptography.hazmat.primitives.asymmetric import ec
from yubihsm.exceptions import YubiHsmInvalidRequestError, YubiHsmDeviceError
from time import sleep
import uuid
import os
import pytest


class TestListObjects:
    def print_list_objects(self, session):
        objlist = session.list_objects()

        for i in range(len(objlist)):
            print(
                "id: ",
                "0x%0.4X" % objlist[i].id,
                ",type: ",
                objlist[i].object_type.name,
                "\t,sequence: ",
                objlist[i].sequence,
            )

        objinfo = objlist[1].get_info()
        print(
            "id: ",
            "0x%0.4X" % objinfo.id,
            ",type: ",
            objinfo.object_type.name,
            "\t,sequence: ",
            objinfo.sequence,
            ",domains: 0x%0.4X" % objinfo.domains,
            ",capabilities: 0x%0.8X" % objinfo.capabilities,
            ",algorithm: ",
            objinfo.algorithm,
        )

    def key_in_list(self, session, keytype, algorithm=None):
        dom = None
        cap = CAPABILITY.NONE
        key_label = "%s%s" % (str(uuid.uuid4()), b"\xf0\x9f\x98\x83".decode())

        key: YhsmObject
        if keytype == OBJECT.ASYMMETRIC_KEY:
            dom = 0xFFFF
            key = AsymmetricKey.generate(session, 0, key_label, dom, cap, algorithm)
        elif keytype == OBJECT.WRAP_KEY:
            dom = 0x01
            key = WrapKey.generate(session, 0, key_label, dom, cap, algorithm, cap)
        elif keytype == OBJECT.HMAC_KEY:
            dom = 0x01
            key = HmacKey.generate(session, 0, key_label, dom, cap, algorithm)
        elif keytype == OBJECT.AUTHENTICATION_KEY:
            dom = 0x01
            key = AuthenticationKey.put_derived(
                session,
                0,
                key_label,
                dom,
                cap,
                cap,
                "password",
            )

        objlist = session.list_objects(object_id=key.id, object_type=key.object_type)
        assert objlist[0].id == key.id
        assert objlist[0].object_type == key.object_type

        objinfo = objlist[0].get_info()
        assert objinfo.id == key.id
        assert objinfo.object_type == key.object_type
        assert objinfo.domains == dom
        assert objinfo.capabilities == cap
        if algorithm:
            assert objinfo.algorithm == algorithm

        if key.object_type == OBJECT.AUTHENTICATION_KEY:
            assert objinfo.origin == ORIGIN.IMPORTED
        else:
            assert objinfo.origin == ORIGIN.GENERATED

        assert objinfo.label == key_label

        key.delete()

    def test_keys_in_list(self, session):
        self.key_in_list(session, OBJECT.ASYMMETRIC_KEY, ALGORITHM.EC_P256)
        self.key_in_list(session, OBJECT.WRAP_KEY, ALGORITHM.AES128_CCM_WRAP)
        self.key_in_list(session, OBJECT.HMAC_KEY, ALGORITHM.HMAC_SHA1)
        self.key_in_list(session, OBJECT.AUTHENTICATION_KEY)

    def test_list_all_params(self, session):
        # TODO: this test should check for presence of some things..
        session.list_objects(
            object_id=1,
            object_type=OBJECT.HMAC_KEY,
            domains=1,
            capabilities=CAPABILITY.ALL,
            algorithm=ALGORITHM.HMAC_SHA1,
            label="foo",
        )


class TestVarious:
    def test_device_info(self, hsm):
        device_info = hsm.get_device_info()
        assert len(device_info.version) == 3
        assert device_info.serial > 0
        assert device_info.log_used > 0
        assert device_info.log_size >= device_info.log_used
        assert len(device_info.supported_algorithms) >= 47
        if device_info.version > (2, 4, 0):
            assert isinstance(device_info.part_number, str)

    def test_get_pseudo_random(self, session):
        data = session.get_pseudo_random(10)
        assert len(data) == 10
        data2 = session.get_pseudo_random(10)
        assert len(data2) == 10
        assert data != data2

    def test_send_too_big(self, hsm):
        buf = os.urandom(MAX_MSG_SIZE - 3 + 1)  # Message 1 byte too large
        with pytest.raises(YubiHsmInvalidRequestError):
            hsm.send_cmd(COMMAND.ECHO, buf)


class TestDevicePublicKey:
    @pytest.fixture(autouse=True)
    def prerequisites(self, info):
        if info.version < (2, 3, 0):
            pytest.skip("Device public keys requires 2.3.0")

    def test_get_device_public_key(self, hsm):
        public_key = hsm.get_device_public_key()
        assert isinstance(public_key, ec.EllipticCurvePublicKey)


class TestEcho:
    def plain_echo(self, hsm, echo_len):
        echo_buf = os.urandom(echo_len)

        resp = hsm.send_cmd(COMMAND.ECHO, echo_buf)

        assert len(resp) == echo_len
        assert resp == echo_buf

    def secure_echo(self, session, echo_len):
        echo_buf = os.urandom(echo_len)

        resp = session.send_secure_cmd(COMMAND.ECHO, echo_buf)
        assert resp == echo_buf

    def test_plain_echo(self, hsm):
        self.plain_echo(hsm, 1024)

    def test_secure_echo(self, session):
        self.secure_echo(session, 1024)

    def test_plain_echo_many(self, hsm):
        for i in range(1, 256):
            self.plain_echo(hsm, i)

    def test_echo_max_size(self, hsm, session):
        self.plain_echo(hsm, 2021)
        self.secure_echo(session, 2021)


class TestFipsOptions:
    @pytest.fixture(scope="class", autouse=True)
    def session2(self, session, connect_hsm):
        try:
            session.get_fips_status()
            session.reset_device()
            sleep(5.0)
            hsm = connect_hsm()
            new_session = hsm.create_session_derived(1, "password")
            yield new_session
            new_session.reset_device()
            sleep(5.0)
        except YubiHsmDeviceError:
            pytest.skip("Non-FIPS YubiHSM")

    def test_set_in_fips_mode(self, session2, info):
        assert session2.get_fips_status() == FipsStatus.OFF
        session2.set_fips_mode(True)
        if info.version < (2, 4, 0):
            assert session2.get_fips_status() == FipsStatus.ON
        else:
            assert session2.get_fips_status() == FipsStatus.PENDING

    def test_fips_mode_disables_algorithms(self, session2, info):
        session2.set_fips_mode(True)
        enabled = session2.get_enabled_algorithms()
        if info.version < (2, 4, 0):
            assert not any(
                enabled[alg]
                for alg in (
                    ALGORITHM.RSA_PKCS1_SHA1,
                    ALGORITHM.RSA_PSS_SHA1,
                    ALGORITHM.EC_ECDSA_SHA1,
                    ALGORITHM.EC_ED25519,
                )
            )
        else:
            assert not any(
                enabled[alg]
                for alg in (
                    ALGORITHM.RSA_PKCS1_SHA1,
                    ALGORITHM.RSA_PSS_SHA1,
                    ALGORITHM.EC_K256,
                    ALGORITHM.EC_ECDSA_SHA1,
                    ALGORITHM.RSA_PKCS1_DECRYPT,
                )
            )

    def test_enabling_algorithms_in_fips_mode(self, session2, info):
        session2.set_fips_mode(True)
        if info.version < (2, 4, 0):
            # For YubiHSM FW < 2.4.0, enabling dissallowed algorithms
            # disables FIPS mode.
            session2.set_enabled_algorithms(
                {
                    ALGORITHM.RSA_PKCS1_SHA1: True,
                }
            )
            assert session2.get_fips_mode() == FipsStatus.OFF
        else:
            with pytest.raises(YubiHsmDeviceError):
                session2.set_enabled_algorithms({ALGORITHM.RSA_PKCS1_SHA1: True})
