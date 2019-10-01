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
from yubihsm.defs import ALGORITHM, CAPABILITY, OBJECT, ERROR
from yubihsm.objects import (
    AuthenticationKey,
    HmacKey,
    Opaque,
    AsymmetricKey,
    OtpAeadKey,
    WrapKey,
)
from yubihsm.exceptions import YubiHsmDeviceError
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from binascii import b2a_hex
import os


class Delete(YubiHsmTestCase):
    def _set_up_key(self, capability):
        password = b2a_hex(self.session.get_pseudo_random(32))
        key = AuthenticationKey.put_derived(
            self.session, 0, "Test Delete authkey", 1, capability, 0, password
        )
        session = self.hsm.create_session_derived(key.id, password)
        return key, session

    def _test_delete(self, obj, capability):
        pos_key, pos_sess = self._set_up_key(capability)
        neg_key, neg_sess = self._set_up_key(CAPABILITY.NONE)

        with self.assertRaises(YubiHsmDeviceError) as context:
            obj.with_session(neg_sess).delete()
        self.assertEqual(context.exception.code, ERROR.INSUFFICIENT_PERMISSIONS)

        obj.with_session(pos_sess).delete()

        pos_sess.close()
        neg_sess.close()
        neg_key.delete()
        pos_key.delete()

    def test_opaque(self):
        obj = Opaque.put(
            self.session, 0, "Test opaque data", 1, 0, OBJECT.OPAQUE, b"data"
        )
        self._test_delete(obj, CAPABILITY.DELETE_OPAQUE)

    def test_authentication_key(self):
        obj = AuthenticationKey.put_derived(
            self.session,
            0,
            "Test delete authkey",
            1,
            CAPABILITY.GET_LOG_ENTRIES,
            0,
            b2a_hex(self.session.get_pseudo_random(32)),
        )
        self._test_delete(obj, CAPABILITY.DELETE_AUTHENTICATION_KEY)

    def test_asymmetric_key(self):
        obj = AsymmetricKey.put(
            self.session,
            0,
            "Test delete asym",
            0xFFFF,
            CAPABILITY.SIGN_ECDSA,
            ec.generate_private_key(ec.SECP384R1(), backend=default_backend()),
        )
        self._test_delete(obj, CAPABILITY.DELETE_ASYMMETRIC_KEY)

    def test_wrap_key(self):
        obj = WrapKey.put(
            self.session,
            0,
            "Test delete",
            1,
            CAPABILITY.IMPORT_WRAPPED,
            ALGORITHM.AES192_CCM_WRAP,
            0,
            os.urandom(24),
        )
        self._test_delete(obj, CAPABILITY.DELETE_WRAP_KEY)

    def test_hmac_key(self):
        obj = HmacKey.put(
            self.session, 0, "Test delete HMAC", 1, CAPABILITY.SIGN_HMAC, b"key"
        )
        self._test_delete(obj, CAPABILITY.DELETE_HMAC_KEY)

    def test_otp_aead_key(self):
        obj = OtpAeadKey.put(
            self.session,
            0,
            "Test delete OTP AEAD",
            1,
            CAPABILITY.DECRYPT_OTP,
            ALGORITHM.AES256_YUBICO_OTP,
            0x00000001,
            os.urandom(32),
        )
        self._test_delete(obj, CAPABILITY.DELETE_OTP_AEAD_KEY)
