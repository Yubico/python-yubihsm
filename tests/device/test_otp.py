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
from yubihsm.objects import OtpAeadKey, OtpData
from yubihsm.exceptions import YubiHsmDeviceError
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.backends import default_backend
from dataclasses import dataclass
import os
import struct
import pytest
from typing import Mapping


@dataclass
class OtpTestVector:
    key: bytes
    id: bytes
    otps: Mapping[str, OtpData]


# From: https://developers.yubico.com/OTP/Specifications/Test_vectors.html
TEST_VECTORS = [
    OtpTestVector(
        key=b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
        id=b"\x01\x02\x03\x04\x05\x06",
        otps={
            "dvgtiblfkbgturecfllberrvkinnctnn": OtpData(1, 1, 1, 1),
            "rnibcnfhdninbrdebccrndfhjgnhftee": OtpData(1, 2, 1, 1),
            "iikkijbdknrrdhfdrjltvgrbkkjblcbh": OtpData(0xFFF, 1, 1, 1),
        },
    ),
    OtpTestVector(
        key=b"\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88",
        id=b"\x88\x88\x88\x88\x88\x88",
        otps={"dcihgvrhjeucvrinhdfddbjhfjftjdei": OtpData(0x8888, 0x88, 0x88, 0x8888)},
    ),
    OtpTestVector(
        key=b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        id=b"\x00\x00\x00\x00\x00\x00",
        otps={"kkkncjnvcnenkjvjgncjihljiibgbhbh": OtpData(0, 0, 0, 0)},
    ),
    OtpTestVector(
        key=b"\xc4\x42\x28\x90\x65\x30\x76\xcd\xe7\x3d\x44\x9b\x19\x1b\x41\x6a",
        id=b"\x33\xc6\x9e\x7f\x24\x9e",
        otps={"iucvrkjiegbhidrcicvlgrcgkgurhjnj": OtpData(1, 0, 0x24, 0x13A7)},
    ),
]


def _crc16(data):
    crc = 0xFFFF
    for b in bytearray(data):
        crc ^= b
        for _ in range(8):
            j = crc & 1
            crc >>= 1
            if j:
                crc ^= 0x8408
    return struct.pack("<H", ~crc & 0xFFFF)


def _construct_otp(aes_key, private_id, otp_data, random_number=0):
    token = private_id + struct.pack(
        "<HHBBH",
        otp_data.use_counter,
        otp_data.timestamp_low,
        otp_data.timestamp_high,
        otp_data.session_counter,
        random_number,
    )
    token += _crc16(token)
    cipher = Cipher(algorithms.AES(aes_key), modes.ECB(), default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(token) + encryptor.finalize()


def test_randomize_aead(session):
    aes_key = os.urandom(16)
    nonce_id = 0x01234567
    key = OtpAeadKey.put(
        session,
        0,
        "Test OTP Randomize AEAD",
        1,
        CAPABILITY.DECRYPT_OTP | CAPABILITY.RANDOMIZE_OTP_AEAD,
        ALGORITHM.AES128_YUBICO_OTP,
        nonce_id,
        aes_key,
    )

    aead = key.randomize_otp_aead()
    assert len(aead) == 36

    # Decrypt generated AEAD
    aes_ccm = AESCCM(aes_key, 8)
    nonce, ct = aead[:6], aead[6:]
    pt = aes_ccm.decrypt(struct.pack("<I6sBBB", nonce_id, nonce, 0, 0, 0), ct, None)

    # Construct an OTP
    otp_data = OtpData(1, 2, 3, 4)
    otp = _construct_otp(pt[:16], pt[16:], otp_data)

    # Compare YubiHSM decrypted output
    assert key.decrypt_otp(aead, otp) == otp_data

    key.delete()


def test_decrypt_invalid_otp(session):
    key = OtpAeadKey.generate(
        session,
        0,
        "Test OTP invalid",
        1,
        CAPABILITY.RANDOMIZE_OTP_AEAD | CAPABILITY.DECRYPT_OTP,
        ALGORITHM.AES128_YUBICO_OTP,
        0x12345678,
    )
    aead = key.randomize_otp_aead()

    with pytest.raises(YubiHsmDeviceError) as context:
        key.decrypt_otp(aead, os.urandom(16))
    assert context.value.code == ERROR.INVALID_OTP

    with pytest.raises(YubiHsmDeviceError) as context:
        key.decrypt_otp(aead, os.urandom(15))
    assert context.value.code, ERROR.WRONG_LENGTH

    key.delete()


def test_otp_vectors(session):
    key1 = OtpAeadKey.generate(
        session,
        0,
        "Test OTP OtpTestVectors",
        1,
        CAPABILITY.CREATE_OTP_AEAD
        | CAPABILITY.REWRAP_FROM_OTP_AEAD_KEY
        | CAPABILITY.DECRYPT_OTP,
        ALGORITHM.AES128_YUBICO_OTP,
        0x12345678,
    )
    key2 = OtpAeadKey.generate(
        session,
        0,
        "Test OTP OtpTestVectors",
        1,
        CAPABILITY.REWRAP_FROM_OTP_AEAD_KEY
        | CAPABILITY.REWRAP_TO_OTP_AEAD_KEY
        | CAPABILITY.DECRYPT_OTP,
        ALGORITHM.AES192_YUBICO_OTP,
        0x87654321,
    )
    keydata = os.urandom(32)
    key3 = OtpAeadKey.put(
        session,
        0,
        "Test OTP OtpTestVectors",
        1,
        CAPABILITY.DECRYPT_OTP
        | CAPABILITY.CREATE_OTP_AEAD
        | CAPABILITY.REWRAP_TO_OTP_AEAD_KEY,
        ALGORITHM.AES256_YUBICO_OTP,
        0x00000001,
        keydata,
    )

    modhex = bytes.maketrans(b"cbdefghijklnrtuv", b"0123456789abcdef")

    for v in TEST_VECTORS:
        aead1 = key1.create_otp_aead(v.key, v.id)
        aead2 = key1.rewrap_otp_aead(key2.id, aead1)
        assert aead1 != aead2

        aead3 = key2.rewrap_otp_aead(key3.id, aead2)
        assert aead1 != aead3
        assert aead2 != aead3
        assert aead1 != key3.create_otp_aead(v.key, v.id)

        for otp, data in v.otps.items():
            otp_bin = bytes.fromhex(otp.translate(modhex))
            assert data == key1.decrypt_otp(aead1, otp_bin)
            assert data == key2.decrypt_otp(aead2, otp_bin)
            assert data == key3.decrypt_otp(aead3, otp_bin)

    key1.delete()
    key2.delete()
    key3.delete()


def test_import_invalid_key_size(session):
    # Key length must match algorithm
    with pytest.raises(ValueError):
        OtpAeadKey.put(
            session,
            0,
            "Test PUT invalid key length",
            0xFFFF,
            CAPABILITY.CREATE_OTP_AEAD
            | CAPABILITY.REWRAP_FROM_OTP_AEAD_KEY
            | CAPABILITY.DECRYPT_OTP,
            ALGORITHM.AES128_YUBICO_OTP,
            0x12345678,
            os.urandom(24),
        )


def test_import_invalid_algorithm(session):
    # Algorithm must be AES128_YUBICO_OTP, AES192_YUBICO_OTP or AES256_YUBICO_OTP
    with pytest.raises(ValueError):
        OtpAeadKey.put(
            session,
            0,
            "Test PUT invalid algorithm",
            0xFFFF,
            CAPABILITY.CREATE_OTP_AEAD
            | CAPABILITY.REWRAP_FROM_OTP_AEAD_KEY
            | CAPABILITY.DECRYPT_OTP,
            ALGORITHM.AES128,
            0x12345678,
            os.urandom(16),
        )
