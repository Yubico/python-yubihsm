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
from yubihsm.objects import AsymmetricKey, WrapKey, Opaque
from yubihsm.exceptions import YubiHsmDeviceError

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os
import random
import pytest


def test_generate_wrap(session):
    w_id = random.randint(1, 0xFFFE)
    a_id = random.randint(1, 0xFFFE)

    wrapkey = WrapKey.generate(
        session,
        w_id,
        "Generate Wrap 0x%04x" % w_id,
        1,
        CAPABILITY.EXPORT_WRAPPED | CAPABILITY.IMPORT_WRAPPED,
        ALGORITHM.AES192_CCM_WRAP,
        CAPABILITY.SIGN_ECDSA | CAPABILITY.EXPORTABLE_UNDER_WRAP,
    )

    asymkey = AsymmetricKey.generate(
        session,
        a_id,
        "Generate Wrap 0x%04x" % a_id,
        0xFFFF,
        CAPABILITY.SIGN_ECDSA | CAPABILITY.EXPORTABLE_UNDER_WRAP,
        ALGORITHM.EC_P256,
    )
    origin = asymkey.get_info().origin
    assert origin == 0x01
    assert origin.generated
    assert not origin.imported
    assert not origin.wrapped

    pub = asymkey.get_public_key()

    data = os.urandom(64)
    resp = asymkey.sign_ecdsa(data)

    pub.verify(resp, data, ec.ECDSA(hashes.SHA256()))

    wrapped = wrapkey.export_wrapped(asymkey)

    wrapped2 = wrapkey.export_wrapped(asymkey)

    assert wrapped != wrapped2

    asymkey.delete()

    pytest.raises(YubiHsmDeviceError, asymkey.get_public_key)

    asymkey = wrapkey.import_wrapped(wrapped)
    origin = asymkey.get_info().origin
    assert origin == 0x11
    assert origin.generated
    assert not origin.imported
    assert origin.wrapped

    data = os.urandom(64)
    resp = asymkey.sign_ecdsa(data)
    assert resp is not None

    pub.verify(resp, data, ec.ECDSA(hashes.SHA256()))

    wrapkey.delete()


def test_export_wrap(session):
    w_id = random.randint(1, 0xFFFE)
    wrapkey = WrapKey.put(
        session,
        w_id,
        "Test Export Wrap 0x%04x" % w_id,
        1,
        CAPABILITY.EXPORT_WRAPPED | CAPABILITY.IMPORT_WRAPPED,
        ALGORITHM.AES192_CCM_WRAP,
        CAPABILITY.SIGN_ECDSA | CAPABILITY.EXPORTABLE_UNDER_WRAP,
        os.urandom(24),
    )

    eckey = ec.generate_private_key(ec.SECP384R1(), backend=default_backend())

    a_id = random.randint(1, 0xFFFE)
    asymkey = AsymmetricKey.put(
        session,
        a_id,
        "Test Export Wrap 0x%04x" % a_id,
        0xFFFF,
        CAPABILITY.SIGN_ECDSA | CAPABILITY.EXPORTABLE_UNDER_WRAP,
        eckey,
    )
    origin = asymkey.get_info().origin
    assert origin == 0x02
    assert not origin.generated
    assert origin.imported
    assert not origin.wrapped

    data = os.urandom(64)
    resp = asymkey.sign_ecdsa(data, hash=hashes.SHA384())

    eckey.public_key().verify(resp, data, ec.ECDSA(hashes.SHA384()))

    wrapped = wrapkey.export_wrapped(asymkey)

    # NOTE: the code below works to decrypt a wrapped object, but relies on
    # understanding the internal object representation which we don't feel
    # like doing here.

    # nonce = wrapped[:13]
    # data = wrapped[13:-8]

    # nonce = '\x01' + nonce + '\x00\x01'

    # decryptor = Cipher(algorithms.AES(wrapkey.key),
    #                    mode=modes.CTR(nonce),
    #                    backend=default_backend()).decryptor()
    # dec = decryptor.update(data)

    # numbers = eckey.private_numbers()
    # serialized = int.from_bytes(numbers.private_value, 'big')
    # assert serialized == dec[-len(serialized):]

    asymkey.delete()

    asymkey = wrapkey.import_wrapped(wrapped)

    data = os.urandom(64)
    resp = asymkey.sign_ecdsa(data, hash=hashes.SHA384())

    eckey.public_key().verify(resp, data, ec.ECDSA(hashes.SHA384()))

    origin = asymkey.get_info().origin
    assert origin == 0x12
    assert not origin.generated
    assert origin.imported
    assert origin.wrapped

    asymkey.delete()

    asymkey = wrapkey.import_wrapped(wrapped)
    assert isinstance(asymkey, AsymmetricKey)


def test_wrap_data(session):
    w_id = random.randint(1, 0xFFFE)
    key_label = "Key in List 0x%04x" % w_id
    key = WrapKey.generate(
        session,
        w_id,
        key_label,
        1,
        CAPABILITY.WRAP_DATA | CAPABILITY.UNWRAP_DATA,
        ALGORITHM.AES256_CCM_WRAP,
        CAPABILITY.NONE,
    )

    for size in (1, 16, 128, 1024, 1989):
        data = os.urandom(size)
        wrapped = key.wrap_data(data)

        data2 = key.unwrap_data(wrapped)
        assert data == data2


def test_more_wrap_data(session):
    w_id = random.randint(1, 0xFFFE)
    key_label = "Key in List 0x%04x" % w_id
    for size in (16, 24, 32):
        if size == 16:
            a = ALGORITHM.AES128_CCM_WRAP
        elif size == 24:
            a = ALGORITHM.AES192_CCM_WRAP
        elif size == 32:
            a = ALGORITHM.AES256_CCM_WRAP
        key = WrapKey.put(
            session,
            w_id,
            key_label,
            1,
            CAPABILITY.WRAP_DATA | CAPABILITY.UNWRAP_DATA,
            a,
            CAPABILITY.NONE,
            os.urandom(size),
        )

        data = os.urandom(size)
        wrap = key.wrap_data(data)
        plain = key.unwrap_data(wrap)
        assert data == plain

        key.delete()


def test_wrap_data_many(session):
    key_label = "wrap key"
    raw_key = os.urandom(24)
    w_key = WrapKey.put(
        session,
        0,
        key_label,
        1,
        CAPABILITY.WRAP_DATA,
        ALGORITHM.AES192_CCM_WRAP,
        CAPABILITY.NONE,
        raw_key,
    )
    u_key = WrapKey.put(
        session,
        0,
        key_label,
        1,
        CAPABILITY.UNWRAP_DATA,
        ALGORITHM.AES192_CCM_WRAP,
        CAPABILITY.NONE,
        raw_key,
    )

    for ln in range(1, 64):
        data = os.urandom(ln)
        wrap = w_key.wrap_data(data)
        with pytest.raises(YubiHsmDeviceError) as context:
            u_key.wrap_data(data)
        assert context.value.code == ERROR.INVALID_DATA
        plain = u_key.unwrap_data(wrap)
        with pytest.raises(YubiHsmDeviceError) as context:
            w_key.unwrap_data(wrap)
        assert context.value.code == ERROR.INVALID_DATA
        assert data == plain


def test_import_wrap_permissions(session):
    key_label = "wrap key"
    raw_key = os.urandom(24)
    opaque = Opaque.put(
        session,
        0,
        "Test Opaque Object",
        0xFFFF,
        CAPABILITY.EXPORTABLE_UNDER_WRAP,
        ALGORITHM.OPAQUE_DATA,
        b"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa",
    )
    w_key = WrapKey.put(
        session,
        0,
        key_label,
        1,
        CAPABILITY.EXPORT_WRAPPED | CAPABILITY.IMPORT_WRAPPED,
        ALGORITHM.AES192_CCM_WRAP,
        CAPABILITY.NONE,
        raw_key,
    )

    with pytest.raises(YubiHsmDeviceError) as context:
        w_key.export_wrapped(opaque)
    assert context.value.code == ERROR.INSUFFICIENT_PERMISSIONS

    w_key.delete()
    w_key = WrapKey.put(
        session,
        0,
        key_label,
        1,
        CAPABILITY.EXPORT_WRAPPED | CAPABILITY.IMPORT_WRAPPED,
        ALGORITHM.AES192_CCM_WRAP,
        CAPABILITY.EXPORTABLE_UNDER_WRAP,
        raw_key,
    )

    w_key.id += 1
    with pytest.raises(YubiHsmDeviceError) as context:
        w_key.export_wrapped(opaque)
    assert context.value.code == ERROR.OBJECT_NOT_FOUND

    w_key.id -= 1
    w_key.delete()
    w_key = WrapKey.put(
        session,
        0,
        key_label,
        1,
        CAPABILITY.IMPORT_WRAPPED,
        ALGORITHM.AES192_CCM_WRAP,
        CAPABILITY.EXPORTABLE_UNDER_WRAP,
        raw_key,
    )

    with pytest.raises(YubiHsmDeviceError) as context:
        w_key.export_wrapped(opaque)
    assert context.value.code == ERROR.INSUFFICIENT_PERMISSIONS

    w_key.delete()
    w_key = WrapKey.put(
        session,
        0,
        key_label,
        1,
        CAPABILITY.EXPORT_WRAPPED,
        ALGORITHM.AES192_CCM_WRAP,
        CAPABILITY.EXPORTABLE_UNDER_WRAP,
        raw_key,
    )

    opaque_wrapped = w_key.export_wrapped(opaque)

    with pytest.raises(YubiHsmDeviceError) as context:
        w_key.import_wrapped(opaque_wrapped)
    assert context.value.code == ERROR.INSUFFICIENT_PERMISSIONS

    w_key.delete()
    w_key = WrapKey.put(
        session,
        0,
        key_label,
        1,
        CAPABILITY.IMPORT_WRAPPED | CAPABILITY.EXPORT_WRAPPED,
        ALGORITHM.AES192_CCM_WRAP,
        CAPABILITY.EXPORTABLE_UNDER_WRAP,
        raw_key,
    )

    opaque_wrapped = w_key.export_wrapped(opaque)
    opaque.delete()
    w_key.id += 1
    with pytest.raises(YubiHsmDeviceError) as context:
        w_key.import_wrapped(opaque_wrapped)
    assert context.value.code == ERROR.OBJECT_NOT_FOUND
    w_key.id -= 1
    opaque = w_key.import_wrapped(opaque_wrapped)

    assert opaque.get() == b"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"


def test_import_wrap_overwrite(session):
    key_label = "wrap key"
    raw_key = os.urandom(24)
    w_key = WrapKey.put(
        session,
        0,
        key_label,
        1,
        CAPABILITY.EXPORT_WRAPPED | CAPABILITY.IMPORT_WRAPPED,
        ALGORITHM.AES192_CCM_WRAP,
        CAPABILITY.EXPORTABLE_UNDER_WRAP,
        raw_key,
    )
    opaque = Opaque.put(
        session,
        0,
        "Test Opaque Object",
        0xFFFF,
        CAPABILITY.EXPORTABLE_UNDER_WRAP,
        ALGORITHM.OPAQUE_DATA,
        b"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa",
    )
    opaque_wrapped = w_key.export_wrapped(opaque)
    with pytest.raises(YubiHsmDeviceError) as context:
        w_key.import_wrapped(opaque_wrapped)
    assert context.value.code == ERROR.OBJECT_EXISTS

    opaque.delete()

    opaque = w_key.import_wrapped(opaque_wrapped)

    assert opaque.get() == b"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
    with pytest.raises(YubiHsmDeviceError) as context:
        opaque = w_key.import_wrapped(opaque_wrapped)
    assert context.value.code == ERROR.OBJECT_EXISTS
