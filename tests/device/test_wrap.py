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

from yubihsm.defs import ALGORITHM, CAPABILITY, ERROR, ORIGIN, OBJECT
from yubihsm.objects import (
    AsymmetricKey,
    SymmetricKey,
    WrapKey,
    Opaque,
    PublicWrapKey,
)
from yubihsm.exceptions import YubiHsmDeviceError

from cryptography.hazmat.primitives.asymmetric import ec, rsa, ed25519
from cryptography.hazmat.primitives import hashes, serialization
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
    assert origin == ORIGIN.GENERATED

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
    assert origin == ORIGIN.IMPORTED_WRAPPED | ORIGIN.GENERATED

    data = os.urandom(64)
    resp = asymkey.sign_ecdsa(data)
    assert resp is not None

    pub.verify(resp, data, ec.ECDSA(hashes.SHA256()))

    wrapkey.delete()
    asymkey.delete()


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
    assert origin == ORIGIN.IMPORTED

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
    assert origin == ORIGIN.IMPORTED_WRAPPED | ORIGIN.IMPORTED

    asymkey.delete()

    asymkey = wrapkey.import_wrapped(wrapped)
    assert isinstance(asymkey, AsymmetricKey)

    wrapkey.delete()
    asymkey.delete()


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

    key.delete()


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

    u_key.delete()
    w_key.delete()


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

    opaque.delete()
    w_key.delete()


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
        w_key.import_wrapped(opaque_wrapped)
    assert context.value.code == ERROR.OBJECT_EXISTS

    opaque.delete()
    w_key.delete()


def test_import_invalid_key_size(session):
    # Key length must match algorithm
    with pytest.raises(ValueError):
        WrapKey.put(
            session,
            0,
            "Test PUT invalid algorithm",
            0xFFFF,
            CAPABILITY.EXPORT_WRAPPED | CAPABILITY.IMPORT_WRAPPED,
            ALGORITHM.AES128_CCM_WRAP,
            CAPABILITY.NONE,
            os.urandom(24),
        )


def test_import_invalid_algorithm(session):
    # Algorithm must be AES128_CCM_WRAP, AES192_CCM_WRAP, AES256_CCM_WRAP,
    # RSA_2048, RSA_3072 or RSA_4096
    with pytest.raises(ValueError):
        WrapKey.put(
            session,
            0,
            "Test PUT invalid algorithm",
            0xFFFF,
            CAPABILITY.EXPORT_WRAPPED | CAPABILITY.IMPORT_WRAPPED,
            ALGORITHM.AES128_YUBICO_OTP,
            CAPABILITY.NONE,
            os.urandom(16),
        )


class TestAsymmetricWrap:
    @pytest.fixture(autouse=True)
    def prerequisites(self, info):
        if info.version < (2, 4, 0):
            pytest.skip("Asymmetric wrap requires 2.4.0")

    def generate_wrap_keys(
        self,
        session,
        export_capabilities,
        export_delegated_capabilities,
        import_delegated_capabilities,
        label,
    ):
        key = rsa.generate_private_key(
            public_exponent=0x10001, key_size=2048, backend=default_backend()
        )

        export_wrapkey = PublicWrapKey.put(
            session,
            0,
            label,
            1,
            CAPABILITY.EXPORT_WRAPPED | export_capabilities,
            CAPABILITY.EXPORTABLE_UNDER_WRAP | export_delegated_capabilities,
            key.public_key(),
        )

        import_wrapkey = WrapKey.put(
            session,
            0,
            label,
            1,
            CAPABILITY.IMPORT_WRAPPED,
            ALGORITHM.RSA_2048,
            import_delegated_capabilities,
            key,
        )
        return export_wrapkey, import_wrapkey

    def test_wrap_asymmetric_key(self, session):
        export_wrapkey, import_wrapkey = self.generate_wrap_keys(
            session,
            CAPABILITY.SIGN_ECDSA,
            CAPABILITY.SIGN_ECDSA,
            CAPABILITY.SIGN_ECDSA,
            "Test Wrap Asymmetric Key",
        )

        asymkey = AsymmetricKey.generate(
            session,
            0,
            "Test Wrap Asymmetric Key",
            0xFFFF,
            CAPABILITY.SIGN_ECDSA | CAPABILITY.EXPORTABLE_UNDER_WRAP,
            ALGORITHM.EC_P256,
        )

        origin = asymkey.get_info().origin
        assert origin == ORIGIN.GENERATED

        pub = asymkey.get_public_key()

        data = os.urandom(64)
        resp = asymkey.sign_ecdsa(data)

        pub.verify(resp, data, ec.ECDSA(hashes.SHA256()))

        wrapped = export_wrapkey.export_raw_key(asymkey)

        wrapped2 = export_wrapkey.export_raw_key(asymkey)

        assert wrapped != wrapped2

        asymkey.delete()

        pytest.raises(YubiHsmDeviceError, asymkey.get_public_key)

        asymkey = import_wrapkey.import_raw_key(
            0,
            OBJECT.ASYMMETRIC_KEY,
            "Test Wrap Asymmetric Key",
            1,
            CAPABILITY.SIGN_ECDSA,
            ALGORITHM.EC_P256,
            wrapped,
        )

        origin = asymkey.get_info().origin
        assert origin == ORIGIN.IMPORTED_WRAPPED | ORIGIN.IMPORTED

        data = os.urandom(64)
        resp = asymkey.sign_ecdsa(data)
        assert resp is not None

        pub.verify(resp, data, ec.ECDSA(hashes.SHA256()))

        import_wrapkey.delete()
        export_wrapkey.delete()

    def test_wrap_symmetric_key(self, session):
        export_wrapkey, import_wrapkey = self.generate_wrap_keys(
            session,
            CAPABILITY.ENCRYPT_ECB | CAPABILITY.DECRYPT_ECB,
            CAPABILITY.DECRYPT_ECB | CAPABILITY.ENCRYPT_ECB,
            CAPABILITY.DECRYPT_ECB,
            "Test Wrap Symmetric Key",
        )

        symkey = SymmetricKey.generate(
            session,
            0,
            "Test Wrap Symmetric Key",
            1,
            CAPABILITY.ENCRYPT_ECB
            | CAPABILITY.DECRYPT_ECB
            | CAPABILITY.EXPORTABLE_UNDER_WRAP,
            ALGORITHM.AES256,
        )

        origin = symkey.get_info().origin
        assert origin == ORIGIN.GENERATED

        pt = os.urandom(256)
        ct = symkey.encrypt_ecb(pt)

        assert pt == symkey.decrypt_ecb(ct)

        wrapped = export_wrapkey.export_raw_key(symkey)

        wrapped2 = export_wrapkey.export_raw_key(symkey)

        assert wrapped != wrapped2

        symkey.delete()

        symkey = import_wrapkey.import_raw_key(
            0,
            OBJECT.SYMMETRIC_KEY,
            "Test Wrap Symmetric Key",
            1,
            CAPABILITY.DECRYPT_ECB,
            ALGORITHM.AES256,
            wrapped,
        )

        origin = symkey.get_info().origin
        assert origin == ORIGIN.IMPORTED_WRAPPED | ORIGIN.IMPORTED

        assert pt == symkey.decrypt_ecb(ct)

        symkey.delete()
        import_wrapkey.delete()
        export_wrapkey.delete()

    def test_export_wrap_rsa(self, session):
        export_wrapkey, import_wrapkey = self.generate_wrap_keys(
            session,
            CAPABILITY.SIGN_ECDSA,
            CAPABILITY.SIGN_ECDSA,
            CAPABILITY.SIGN_ECDSA | CAPABILITY.EXPORTABLE_UNDER_WRAP,
            "Test Export RSA",
        )

        asymkey = AsymmetricKey.generate(
            session,
            0,
            "Test Export RSA",
            0xFFFF,
            CAPABILITY.SIGN_ECDSA | CAPABILITY.EXPORTABLE_UNDER_WRAP,
            ALGORITHM.EC_P256,
        )

        origin = asymkey.get_info().origin
        assert origin == ORIGIN.GENERATED

        pub = asymkey.get_public_key()

        data = os.urandom(64)
        resp = asymkey.sign_ecdsa(data)

        pub.verify(resp, data, ec.ECDSA(hashes.SHA256()))

        wrapped = export_wrapkey.export_wrapped_rsa(asymkey)

        wrapped2 = export_wrapkey.export_wrapped_rsa(asymkey)

        assert wrapped != wrapped2

        asymkey.delete()

        pytest.raises(YubiHsmDeviceError, asymkey.get_public_key)

        asymkey = import_wrapkey.import_wrapped_rsa(wrapped)

        origin = asymkey.get_info().origin
        assert origin == ORIGIN.IMPORTED_WRAPPED | ORIGIN.GENERATED

        data = os.urandom(64)
        resp = asymkey.sign_ecdsa(data)
        assert resp is not None

        pub.verify(resp, data, ec.ECDSA(hashes.SHA256()))

        asymkey.delete()
        import_wrapkey.delete()
        export_wrapkey.delete()

    def test_export_using_private_wrapkey(self, session):
        _, private_wrapkey = self.generate_wrap_keys(
            session,
            CAPABILITY.SIGN_ECDSA,
            CAPABILITY.SIGN_ECDSA,
            CAPABILITY.SIGN_ECDSA | CAPABILITY.EXPORTABLE_UNDER_WRAP,
            "Test Export Using Private Wrapkey",
        )

        asymkey = AsymmetricKey.generate(
            session,
            0,
            "Test Export Using Private Wrapkey",
            0xFFFF,
            CAPABILITY.SIGN_ECDSA | CAPABILITY.EXPORTABLE_UNDER_WRAP,
            ALGORITHM.EC_P256,
        )

        with pytest.raises(YubiHsmDeviceError) as context:
            # The (private) wrap key is only used for importing
            # wrapped objects.
            private_wrapkey.export_wrapped(asymkey)
        assert context.value.code == ERROR.INVALID_DATA

        asymkey.delete()
        private_wrapkey.delete()

    def test_get_public_key(self, session):
        import_key = rsa.generate_private_key(
            public_exponent=0x10001, key_size=2048, backend=default_backend()
        )
        export_key = rsa.generate_private_key(
            public_exponent=0x10001, key_size=2048, backend=default_backend()
        )

        export_wrapkey = PublicWrapKey.put(
            session,
            0,
            "Test Get Public Key (PublicWrapKey)",
            1,
            CAPABILITY.EXPORT_WRAPPED,
            CAPABILITY.EXPORTABLE_UNDER_WRAP,
            export_key.public_key(),
        )
        import_wrapkey = WrapKey.put(
            session,
            0,
            "Test Get Public Key (WrapKey)",
            1,
            CAPABILITY.EXPORT_WRAPPED,
            ALGORITHM.RSA_2048,
            CAPABILITY.NONE,
            import_key,
        )

        import_pub = import_wrapkey.get_public_key()
        export_pub = export_wrapkey.get_public_key()
        assert import_pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ) == import_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        assert export_pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ) == export_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        import_wrapkey.delete()
        export_wrapkey.delete()

    def test_export_ed25519(self, session):
        wrapkey = WrapKey.put(
            session,
            0,
            "Test Export ED25519",
            1,
            CAPABILITY.EXPORT_WRAPPED | CAPABILITY.IMPORT_WRAPPED,
            ALGORITHM.AES192_CCM_WRAP,
            CAPABILITY.SIGN_EDDSA | CAPABILITY.EXPORTABLE_UNDER_WRAP,
            os.urandom(24),
        )

        edkey = ed25519.Ed25519PrivateKey.generate()

        asymkey = AsymmetricKey.put(
            session,
            0,
            "Test Export ED25519",
            0xFFFF,
            CAPABILITY.SIGN_EDDSA | CAPABILITY.EXPORTABLE_UNDER_WRAP,
            edkey,
        )
        origin = asymkey.get_info().origin
        assert origin == ORIGIN.IMPORTED

        data = os.urandom(64)
        resp = asymkey.sign_eddsa(data)

        edkey.public_key().verify(resp, data)

        wrapped = wrapkey.export_wrapped(asymkey)
        wrapped_with_seed = wrapkey.export_wrapped(asymkey, True)

        asymkey.delete()

        for w in [wrapped, wrapped_with_seed]:
            asymkey = wrapkey.import_wrapped(w)

            data = os.urandom(64)
            resp = asymkey.sign_eddsa(data)

            edkey.public_key().verify(resp, data)

            origin = asymkey.get_info().origin
            assert origin == ORIGIN.IMPORTED_WRAPPED | ORIGIN.IMPORTED

            asymkey.delete()

        wrapkey.delete()
