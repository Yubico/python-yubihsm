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

from yubihsm.defs import ALGORITHM, CAPABILITY
from yubihsm.objects import SymmetricKey

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from typing import Optional
import os
import pytest

AES_ALGORITHMS = (ALGORITHM.AES128, ALGORITHM.AES192, ALGORITHM.AES256)
AES_CAPABILITIES = (
    CAPABILITY.ENCRYPT_ECB
    | CAPABILITY.DECRYPT_ECB
    | CAPABILITY.ENCRYPT_CBC
    | CAPABILITY.DECRYPT_CBC
)


@pytest.fixture(autouse=True, scope="module")
def prerequisites(info):
    if info.version < (2, 3, 0):
        pytest.skip("Symmetric keys require YubiHSM 2.3.0")


@pytest.fixture(scope="module", params=AES_ALGORITHMS)
def generated_key(session, request):
    algorithm = request.param
    key = SymmetricKey.generate(
        session,
        0,
        "Generated AES Key %x" % algorithm,
        0xFFFF,
        AES_CAPABILITIES,
        algorithm,
    )
    yield key
    key.delete()


@pytest.fixture(scope="module", params=AES_ALGORITHMS)
def imported_key(session, request):
    algorithm = request.param
    key_to_import = os.urandom(algorithm.to_key_size())

    key = SymmetricKey.put(
        session,
        0,
        "Imported AES Key %x" % algorithm,
        0xFFFF,
        AES_CAPABILITIES,
        algorithm,
        key_to_import,
    )
    yield key, key_to_import
    key.delete()


def test_import_invalid_key_size(session):
    # Key length must match algorithm
    with pytest.raises(ValueError):
        SymmetricKey.put(
            session,
            0,
            "Test PUT invalid key length",
            0xFFFF,
            AES_CAPABILITIES,
            ALGORITHM.AES128,
            os.urandom(24),
        )


def test_import_invalid_algorithm(session):
    # Algorithm must be AES128, AES192 or AES256
    with pytest.raises(ValueError):
        SymmetricKey.put(
            session,
            0,
            "Test PUT invalid algorithm",
            0xFFFF,
            AES_CAPABILITIES,
            ALGORITHM.AES128_CCM_WRAP,
            os.urandom(16),
        )


class TestSymmetricECB:
    def validate_ecb(self, keyobj: SymmetricKey, key: Optional[bytes] = None):
        pt = os.urandom(256)
        ct = keyobj.encrypt_ecb(pt)
        if key:
            encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
            assert ct == encryptor.update(pt) + encryptor.finalize()
        assert pt == keyobj.decrypt_ecb(ct)

    def test_ecb_generated_key(self, generated_key):
        self.validate_ecb(generated_key)

    def test_ecb_imported_key(self, imported_key):
        self.validate_ecb(*imported_key)


class TestSymmetricCBC:
    def validate_cbc(self, keyobj: SymmetricKey, key: Optional[bytes] = None):
        pt = os.urandom(256)
        iv = os.urandom(16)
        ct = keyobj.encrypt_cbc(iv, pt)
        if key:
            encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
            assert ct == encryptor.update(pt) + encryptor.finalize()
        assert pt == keyobj.decrypt_cbc(iv, ct)

    def test_cbc_generated_key(self, generated_key):
        self.validate_cbc(generated_key)

    def test_cbc_imported_key(self, imported_key):
        self.validate_cbc(*imported_key)
