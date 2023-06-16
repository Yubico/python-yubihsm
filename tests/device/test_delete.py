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

from yubihsm.defs import ALGORITHM, CAPABILITY, ERROR
from yubihsm.objects import (
    AuthenticationKey,
    HmacKey,
    Opaque,
    AsymmetricKey,
    OtpAeadKey,
    WrapKey,
    SymmetricKey,
)
from yubihsm.exceptions import YubiHsmDeviceError
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
import os
import pytest


def _set_up_key(hsm, session, capability):
    password = session.get_pseudo_random(32).hex()
    key = AuthenticationKey.put_derived(
        session, 0, "Test Delete authkey", 1, capability, CAPABILITY.NONE, password
    )
    session = hsm.create_session_derived(key.id, password)
    return key, session


def _test_delete(hsm, session, obj, capability):
    pos_key, pos_sess = _set_up_key(hsm, session, capability)
    neg_key, neg_sess = _set_up_key(hsm, session, CAPABILITY.NONE)

    with pytest.raises(YubiHsmDeviceError) as context:
        obj.with_session(neg_sess).delete()
    assert context.value.code == ERROR.INSUFFICIENT_PERMISSIONS

    obj.with_session(pos_sess).delete()

    pos_sess.close()
    neg_sess.close()
    neg_key.delete()
    pos_key.delete()


def test_opaque(hsm, session):
    obj = Opaque.put(
        session,
        0,
        "Test opaque data",
        1,
        CAPABILITY.NONE,
        ALGORITHM.OPAQUE_DATA,
        b"data",
    )
    _test_delete(hsm, session, obj, CAPABILITY.DELETE_OPAQUE)


def test_authentication_key(hsm, session):
    obj = AuthenticationKey.put_derived(
        session,
        0,
        "Test delete authkey",
        1,
        CAPABILITY.GET_LOG_ENTRIES,
        CAPABILITY.NONE,
        session.get_pseudo_random(32).hex(),
    )
    _test_delete(hsm, session, obj, CAPABILITY.DELETE_AUTHENTICATION_KEY)


def test_asymmetric_key(hsm, session):
    obj = AsymmetricKey.put(
        session,
        0,
        "Test delete asym",
        0xFFFF,
        CAPABILITY.SIGN_ECDSA,
        ec.generate_private_key(ec.SECP384R1(), backend=default_backend()),
    )
    _test_delete(hsm, session, obj, CAPABILITY.DELETE_ASYMMETRIC_KEY)


def test_wrap_key(hsm, session):
    obj = WrapKey.put(
        session,
        0,
        "Test delete",
        1,
        CAPABILITY.IMPORT_WRAPPED,
        ALGORITHM.AES192_CCM_WRAP,
        CAPABILITY.NONE,
        os.urandom(24),
    )
    _test_delete(hsm, session, obj, CAPABILITY.DELETE_WRAP_KEY)


def test_hmac_key(hsm, session):
    obj = HmacKey.put(session, 0, "Test delete HMAC", 1, CAPABILITY.SIGN_HMAC, b"key")
    _test_delete(hsm, session, obj, CAPABILITY.DELETE_HMAC_KEY)


def test_otp_aead_key(hsm, session):
    obj = OtpAeadKey.put(
        session,
        0,
        "Test delete OTP AEAD",
        1,
        CAPABILITY.DECRYPT_OTP,
        ALGORITHM.AES256_YUBICO_OTP,
        0x00000001,
        os.urandom(32),
    )
    _test_delete(hsm, session, obj, CAPABILITY.DELETE_OTP_AEAD_KEY)


def test_symmetric_key(hsm, session, info):
    if info.version < (2, 3, 0):
        pytest.skip("Symmetric keys require YubiHSM 2.3.0")

    obj = SymmetricKey.put(
        session,
        0,
        "Test delete symmetric",
        0xFFFF,
        CAPABILITY.DECRYPT_ECB,
        ALGORITHM.AES128,
        os.urandom(16),
    )
    _test_delete(hsm, session, obj, CAPABILITY.DELETE_SYMMETRIC_KEY)
