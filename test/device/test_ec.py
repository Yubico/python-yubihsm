# coding=utf-8

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
from yubihsm.defs import ALGORITHM, CAPABILITY, COMMAND, ERROR
from yubihsm.defs import BRAINPOOLP256R1, BRAINPOOLP384R1, BRAINPOOLP512R1
from yubihsm.eddsa import load_ed25519_private_key, serialize_ed25519_public_key
from yubihsm.objects import AsymmetricKey
from yubihsm.exceptions import YubiHsmDeviceError

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, utils as crypto_utils
from binascii import a2b_hex
import os
import struct


class TestSecpEcdsa(YubiHsmTestCase):
    def secp_ecdsa_sign(self, curve, hashtype, length=0):
        key = ec.generate_private_key(curve, backend=default_backend())

        asymkey = AsymmetricKey.put(
            self.session, 0, "SECP ECDSA Sign Sign", 0xFFFF, CAPABILITY.SIGN_ECDSA, key
        )

        data = os.urandom(64)
        resp = asymkey.sign_ecdsa(data, hash=hashtype, length=length)

        key.public_key().verify(resp, data, ec.ECDSA(hashtype))

        asymkey.delete()

    def secp_derive_ecdh(self, curve):
        devkey = ec.generate_private_key(curve, backend=default_backend())

        asymkey = AsymmetricKey.put(
            self.session,
            0,
            "SECP ECDSA Decrypt",
            0xFFFF,
            CAPABILITY.DERIVE_ECDH,
            devkey,
        )

        ekey = ec.generate_private_key(curve, backend=default_backend())
        secret = ekey.exchange(ec.ECDH(), devkey.public_key())

        resp = asymkey.derive_ecdh(ekey.public_key())
        self.assertEqual(secret, resp)

        asymkey.delete()

    def test_secp224r1_ecdsa_sign(self):
        self.secp_ecdsa_sign(ec.SECP224R1(), hashes.SHA1())
        self.secp_ecdsa_sign(ec.SECP224R1(), hashes.SHA256(), length=28)
        self.secp_ecdsa_sign(ec.SECP224R1(), hashes.SHA384(), length=28)
        self.secp_ecdsa_sign(ec.SECP224R1(), hashes.SHA512(), length=28)

    def test_secp224r1_ecdsa_sign_truncated(self):
        self.require_version((2, 1, 0), "Automatic digest truncation")

        self.secp_ecdsa_sign(ec.SECP224R1(), hashes.SHA256())
        self.secp_ecdsa_sign(ec.SECP224R1(), hashes.SHA384())
        self.secp_ecdsa_sign(ec.SECP224R1(), hashes.SHA512())

    def test_secp256r1_ecdsa_sign(self):
        self.secp_ecdsa_sign(ec.SECP256R1(), hashes.SHA1())
        self.secp_ecdsa_sign(ec.SECP256R1(), hashes.SHA256())
        self.secp_ecdsa_sign(ec.SECP256R1(), hashes.SHA384(), length=32)
        self.secp_ecdsa_sign(ec.SECP256R1(), hashes.SHA512(), length=32)

    def test_secp256r1_ecdsa_sign_truncated(self):
        self.require_version((2, 1, 0), "Automatic digest truncation")

        self.secp_ecdsa_sign(ec.SECP256R1(), hashes.SHA384())
        self.secp_ecdsa_sign(ec.SECP256R1(), hashes.SHA512())

    def test_secp384r1_ecdsa_sign(self):
        self.secp_ecdsa_sign(ec.SECP384R1(), hashes.SHA1())
        self.secp_ecdsa_sign(ec.SECP384R1(), hashes.SHA256())
        self.secp_ecdsa_sign(ec.SECP384R1(), hashes.SHA384())
        self.secp_ecdsa_sign(ec.SECP384R1(), hashes.SHA512(), length=48)

    def test_secp384r1_ecdsa_sign_truncated(self):
        self.require_version((2, 1, 0), "Automatic digest truncation")

        self.secp_ecdsa_sign(ec.SECP384R1(), hashes.SHA512())

    def test_secp521r1_ecdsa_sign(self):
        self.secp_ecdsa_sign(ec.SECP521R1(), hashes.SHA1())
        self.secp_ecdsa_sign(ec.SECP521R1(), hashes.SHA256())
        self.secp_ecdsa_sign(ec.SECP521R1(), hashes.SHA384())
        self.secp_ecdsa_sign(ec.SECP521R1(), hashes.SHA512())
        self.secp_ecdsa_sign(ec.SECP521R1(), hashes.SHA512(), length=66)

    def test_secp256k1_ecdsa_sign(self):
        self.secp_ecdsa_sign(ec.SECP256K1(), hashes.SHA1())
        self.secp_ecdsa_sign(ec.SECP256K1(), hashes.SHA256())
        self.secp_ecdsa_sign(ec.SECP256K1(), hashes.SHA384(), length=32)
        self.secp_ecdsa_sign(ec.SECP256K1(), hashes.SHA512(), length=32)

    def test_secp256k1_ecdsa_sign_truncated(self):
        self.require_version((2, 1, 0), "Automatic digest truncation")

        self.secp_ecdsa_sign(ec.SECP256K1(), hashes.SHA384())
        self.secp_ecdsa_sign(ec.SECP256K1(), hashes.SHA512())

    def test_secp224r1_derive_ecdh(self):
        self.secp_derive_ecdh(ec.SECP224R1())

    def test_secp256r1_derive_ecdh(self):
        self.secp_derive_ecdh(ec.SECP256R1())

    def test_secp384r1_derive_ecdh(self):
        self.secp_derive_ecdh(ec.SECP384R1())

    def test_secp521r1_derive_ecdh(self):
        self.secp_derive_ecdh(ec.SECP521R1())

    def test_secp256k1_derive_ecdh(self):
        self.secp_derive_ecdh(ec.SECP256K1())

    def test_bad_ecdh_keys(self):
        pubkeys = [
            # this is a public key not on the curve (p256)
            "04cdeb39edd03e2b1a11a5e134ec99d5f25f21673d403f3ecb47bd1fa676638958ea58493b8429598c0b49bbb85c3303ddb1553c3b761c2caacca71606ba9ebaca",  # noqa E501
            # all zeroes public key
            "0400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",  # noqa E501
            # all ff public key
            "04ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",  # noqa E501
        ]

        key = AsymmetricKey.generate(
            self.session,
            0,
            "badkey ecdh test",
            0xFFFF,
            CAPABILITY.DERIVE_ECDH,
            ALGORITHM.EC_P256,
        )
        keyid = struct.pack("!H", key.id)
        for pubkey in pubkeys:
            with self.assertRaises(YubiHsmDeviceError) as context:
                self.session.send_secure_cmd(
                    COMMAND.DERIVE_ECDH, keyid + a2b_hex(pubkey)
                )
            self.assertEqual(context.exception.code, ERROR.INVALID_DATA)
        key.delete()

    def test_biased_k(self):
        # n is the order of the p256r1 curve.
        n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

        key = ec.generate_private_key(ec.SECP256R1(), backend=default_backend())
        d = key.private_numbers().private_value
        asymkey = AsymmetricKey.put(
            self.session, 0, "Test ECDSA K", 0xFFFF, CAPABILITY.SIGN_ECDSA, key
        )

        data = b"Hello World!"

        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(data)
        h = int.from_bytes(digest.finalize(), "big")

        # The assumption here is that for 1024 runs we should get a distribution
        # where each single bit is set between 400 and 1024 - 400 times.
        count = 1024
        mincount = 400

        bits = [0] * 256
        for i in range(0, count):
            resp = asymkey.sign_ecdsa(data, hash=hashes.SHA256())
            # Extract random number k from signature:
            # k = s^(-1) * (h + d*r) mod n
            (r, s) = crypto_utils.decode_dss_signature(resp)
            # Fermat's little theorem: a^(p-1) ≡ 1 (mod p), when p is prime.
            # s * s^(p-2) ≡ 1 (mod p)
            s_inv = pow(s, n - 2, n)
            k = s_inv * (h + d * r) % n
            for j in range(0, 256):
                if (k >> j) & 1:
                    bits[j] += 1

        for bit in bits:
            self.assertGreater(bit, mincount)
            self.assertLess(bit, count - mincount)

        asymkey.delete()


class TestBpR1Ecdsa(YubiHsmTestCase):
    def bp_r1_ecdsa_sign(self, curve, hashtype):
        key = ec.generate_private_key(curve, backend=default_backend())

        asymkey = AsymmetricKey.put(
            self.session, 0, "BP R1 ECDSA Sign", 0xFFFF, CAPABILITY.SIGN_ECDSA, key
        )

        data = os.urandom(64)
        resp = asymkey.sign_ecdsa(data, hash=hashtype)

        key.public_key().verify(resp, data, ec.ECDSA(hashtype))

        asymkey.delete()

    def bp_r1_derive_ecdh(self, curve):
        devkey = ec.generate_private_key(curve, backend=default_backend())

        asymkey = AsymmetricKey.put(
            self.session,
            0,
            "BP R1 ECDSA Decrypt",
            0xFFFF,
            CAPABILITY.DERIVE_ECDH,
            devkey,
        )

        ekey = ec.generate_private_key(curve, backend=default_backend())
        secret = ekey.exchange(ec.ECDH(), devkey.public_key())

        resp = asymkey.derive_ecdh(ekey.public_key())
        self.assertEqual(secret, resp)

        asymkey.delete()

    def test_bp256r1_ecdsa_sign(self):
        self.bp_r1_ecdsa_sign(BRAINPOOLP256R1(), hashes.SHA256())

    def test_bp384r1_ecdsa_sign(self):
        self.bp_r1_ecdsa_sign(BRAINPOOLP384R1(), hashes.SHA384())

    def test_bp512r1_ecdsa_sign(self):
        self.bp_r1_ecdsa_sign(BRAINPOOLP512R1(), hashes.SHA512())

    def test_bp256r1_derive_ecdh(self):
        self.bp_r1_derive_ecdh(BRAINPOOLP256R1())

    def test_bp384r1_derive_ecdh(self):
        self.bp_r1_derive_ecdh(BRAINPOOLP384R1())

    def test_bp512r1_derive_ecdh(self):
        self.bp_r1_derive_ecdh(BRAINPOOLP512R1())


class TestBpR1(YubiHsmTestCase):
    def generate_bp_r1_sign(self, curve, hashtype):
        asymkey = AsymmetricKey.generate(
            self.session, 0, "Generate BP R1 Sign", 0xFFFF, CAPABILITY.SIGN_ECDSA, curve
        )

        pub = asymkey.get_public_key()

        data = os.urandom(64)
        resp = asymkey.sign_ecdsa(data, hashtype)

        pub.verify(resp, data, ec.ECDSA(hashtype))

        asymkey.delete()

    def test_generate_bp256r1_sign(self):
        self.generate_bp_r1_sign(ALGORITHM.EC_BP256, hashes.SHA256())

    def test_generate_bp384r1_sign(self):
        self.generate_bp_r1_sign(ALGORITHM.EC_BP384, hashes.SHA384())

    def test_generate_bp512r1_sign(self):
        self.generate_bp_r1_sign(ALGORITHM.EC_BP512, hashes.SHA512())


class TestSecp(YubiHsmTestCase):
    def generate_secp_sign(self, curve, hashtype, length=0):
        asymkey = AsymmetricKey.generate(
            self.session, 0, "Generate SECP Sign", 0xFFFF, CAPABILITY.SIGN_ECDSA, curve
        )

        pub = asymkey.get_public_key()

        data = os.urandom(64)
        resp = asymkey.sign_ecdsa(data, hash=hashtype, length=length)

        pub.verify(resp, data, ec.ECDSA(hashtype))

        asymkey.delete()

    def test_generate_secp224r1_sign(self):
        self.generate_secp_sign(ALGORITHM.EC_P224, hashes.SHA1())

    def test_generate_secp256r1_sign(self):
        self.generate_secp_sign(ALGORITHM.EC_P256, hashes.SHA256())

    def test_generate_secp384r1_sign(self):
        self.generate_secp_sign(ALGORITHM.EC_P384, hashes.SHA384())

    def test_generate_secp521r1_sign(self):
        self.generate_secp_sign(ALGORITHM.EC_P521, hashes.SHA512(), length=66)

    def test_generate_secp256k1_sign(self):
        self.generate_secp_sign(ALGORITHM.EC_K256, hashes.SHA256())


class TestP256Pubkey(YubiHsmTestCase):
    def pubkey_p256(self, curve):
        key = ec.generate_private_key(curve, backend=default_backend())

        asymkey = AsymmetricKey.put(self.session, 0, "P256 Pubkey", 0xFFFF, 0, key)

        pub = asymkey.get_public_key()
        self.assertEqual(
            pub.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ),
            key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ),
        )

        asymkey.delete()

    def test_pubkey_p256(self):
        self.pubkey_p256(ec.SECP256R1())


class TestEd25519(YubiHsmTestCase):

    vectors = [
        {
            "key": b"\x9d\x61\xb1\x9d\xef\xfd\x5a\x60\xba\x84\x4a\xf4\x92\xec\x2c\xc4\x44\x49\xc5\x69\x7b\x32\x69\x19\x70\x3b\xac\x03\x1c\xae\x7f\x60",  # noqa E501
            "pubkey": b"\xd7\x5a\x98\x01\x82\xb1\x0a\xb7\xd5\x4b\xfe\xd3\xc9\x64\x07\x3a\x0e\xe1\x72\xf3\xda\xa6\x23\x25\xaf\x02\x1a\x68\xf7\x07\x51\x1a",  # noqa E501
            "msg": b"",
            "sig": b"\xe5\x56\x43\x00\xc3\x60\xac\x72\x90\x86\xe2\xcc\x80\x6e\x82\x8a\x84\x87\x7f\x1e\xb8\xe5\xd9\x74\xd8\x73\xe0\x65\x22\x49\x01\x55\x5f\xb8\x82\x15\x90\xa3\x3b\xac\xc6\x1e\x39\x70\x1c\xf9\xb4\x6b\xd2\x5b\xf5\xf0\x59\x5b\xbe\x24\x65\x51\x41\x43\x8e\x7a\x10\x0b",  # noqa E501
        },
        {
            "key": b"\x4c\xcd\x08\x9b\x28\xff\x96\xda\x9d\xb6\xc3\x46\xec\x11\x4e\x0f\x5b\x8a\x31\x9f\x35\xab\xa6\x24\xda\x8c\xf6\xed\x4f\xb8\xa6\xfb",  # noqa E501
            "pubkey": b"\x3d\x40\x17\xc3\xe8\x43\x89\x5a\x92\xb7\x0a\xa7\x4d\x1b\x7e\xbc\x9c\x98\x2c\xcf\x2e\xc4\x96\x8c\xc0\xcd\x55\xf1\x2a\xf4\x66\x0c",  # noqa E501
            "msg": b"\x72",
            "sig": b"\x92\xa0\x09\xa9\xf0\xd4\xca\xb8\x72\x0e\x82\x0b\x5f\x64\x25\x40\xa2\xb2\x7b\x54\x16\x50\x3f\x8f\xb3\x76\x22\x23\xeb\xdb\x69\xda\x08\x5a\xc1\xe4\x3e\x15\x99\x6e\x45\x8f\x36\x13\xd0\xf1\x1d\x8c\x38\x7b\x2e\xae\xb4\x30\x2a\xee\xb0\x0d\x29\x16\x12\xbb\x0c\x00",  # noqa E501
        },
        {
            "key": b"\xc5\xaa\x8d\xf4\x3f\x9f\x83\x7b\xed\xb7\x44\x2f\x31\xdc\xb7\xb1\x66\xd3\x85\x35\x07\x6f\x09\x4b\x85\xce\x3a\x2e\x0b\x44\x58\xf7",  # noqa E501
            "pubkey": b"\xfc\x51\xcd\x8e\x62\x18\xa1\xa3\x8d\xa4\x7e\xd0\x02\x30\xf0\x58\x08\x16\xed\x13\xba\x33\x03\xac\x5d\xeb\x91\x15\x48\x90\x80\x25",  # noqa E501
            "msg": b"\xaf\x82",
            "sig": b"\x62\x91\xd6\x57\xde\xec\x24\x02\x48\x27\xe6\x9c\x3a\xbe\x01\xa3\x0c\xe5\x48\xa2\x84\x74\x3a\x44\x5e\x36\x80\xd7\xdb\x5a\xc3\xac\x18\xff\x9b\x53\x8d\x16\xf2\x90\xae\x67\xf7\x60\x98\x4d\xc6\x59\x4a\x7c\x15\xe9\x71\x6e\xd2\x8d\xc0\x27\xbe\xce\xea\x1e\xc4\x0a",  # noqa E501
        },
        {
            "key": b"\xf5\xe5\x76\x7c\xf1\x53\x31\x95\x17\x63\x0f\x22\x68\x76\xb8\x6c\x81\x60\xcc\x58\x3b\xc0\x13\x74\x4c\x6b\xf2\x55\xf5\xcc\x0e\xe5",  # noqa E501
            "pubkey": b"\x27\x81\x17\xfc\x14\x4c\x72\x34\x0f\x67\xd0\xf2\x31\x6e\x83\x86\xce\xff\xbf\x2b\x24\x28\xc9\xc5\x1f\xef\x7c\x59\x7f\x1d\x42\x6e",  # noqa E501
            "msg": b"\x08\xb8\xb2\xb7\x33\x42\x42\x43\x76\x0f\xe4\x26\xa4\xb5\x49\x08\x63\x21\x10\xa6\x6c\x2f\x65\x91\xea\xbd\x33\x45\xe3\xe4\xeb\x98\xfa\x6e\x26\x4b\xf0\x9e\xfe\x12\xee\x50\xf8\xf5\x4e\x9f\x77\xb1\xe3\x55\xf6\xc5\x05\x44\xe2\x3f\xb1\x43\x3d\xdf\x73\xbe\x84\xd8\x79\xde\x7c\x00\x46\xdc\x49\x96\xd9\xe7\x73\xf4\xbc\x9e\xfe\x57\x38\x82\x9a\xdb\x26\xc8\x1b\x37\xc9\x3a\x1b\x27\x0b\x20\x32\x9d\x65\x86\x75\xfc\x6e\xa5\x34\xe0\x81\x0a\x44\x32\x82\x6b\xf5\x8c\x94\x1e\xfb\x65\xd5\x7a\x33\x8b\xbd\x2e\x26\x64\x0f\x89\xff\xbc\x1a\x85\x8e\xfc\xb8\x55\x0e\xe3\xa5\xe1\x99\x8b\xd1\x77\xe9\x3a\x73\x63\xc3\x44\xfe\x6b\x19\x9e\xe5\xd0\x2e\x82\xd5\x22\xc4\xfe\xba\x15\x45\x2f\x80\x28\x8a\x82\x1a\x57\x91\x16\xec\x6d\xad\x2b\x3b\x31\x0d\xa9\x03\x40\x1a\xa6\x21\x00\xab\x5d\x1a\x36\x55\x3e\x06\x20\x3b\x33\x89\x0c\xc9\xb8\x32\xf7\x9e\xf8\x05\x60\xcc\xb9\xa3\x9c\xe7\x67\x96\x7e\xd6\x28\xc6\xad\x57\x3c\xb1\x16\xdb\xef\xef\xd7\x54\x99\xda\x96\xbd\x68\xa8\xa9\x7b\x92\x8a\x8b\xbc\x10\x3b\x66\x21\xfc\xde\x2b\xec\xa1\x23\x1d\x20\x6b\xe6\xcd\x9e\xc7\xaf\xf6\xf6\xc9\x4f\xcd\x72\x04\xed\x34\x55\xc6\x8c\x83\xf4\xa4\x1d\xa4\xaf\x2b\x74\xef\x5c\x53\xf1\xd8\xac\x70\xbd\xcb\x7e\xd1\x85\xce\x81\xbd\x84\x35\x9d\x44\x25\x4d\x95\x62\x9e\x98\x55\xa9\x4a\x7c\x19\x58\xd1\xf8\xad\xa5\xd0\x53\x2e\xd8\xa5\xaa\x3f\xb2\xd1\x7b\xa7\x0e\xb6\x24\x8e\x59\x4e\x1a\x22\x97\xac\xbb\xb3\x9d\x50\x2f\x1a\x8c\x6e\xb6\xf1\xce\x22\xb3\xde\x1a\x1f\x40\xcc\x24\x55\x41\x19\xa8\x31\xa9\xaa\xd6\x07\x9c\xad\x88\x42\x5d\xe6\xbd\xe1\xa9\x18\x7e\xbb\x60\x92\xcf\x67\xbf\x2b\x13\xfd\x65\xf2\x70\x88\xd7\x8b\x7e\x88\x3c\x87\x59\xd2\xc4\xf5\xc6\x5a\xdb\x75\x53\x87\x8a\xd5\x75\xf9\xfa\xd8\x78\xe8\x0a\x0c\x9b\xa6\x3b\xcb\xcc\x27\x32\xe6\x94\x85\xbb\xc9\xc9\x0b\xfb\xd6\x24\x81\xd9\x08\x9b\xec\xcf\x80\xcf\xe2\xdf\x16\xa2\xcf\x65\xbd\x92\xdd\x59\x7b\x07\x07\xe0\x91\x7a\xf4\x8b\xbb\x75\xfe\xd4\x13\xd2\x38\xf5\x55\x5a\x7a\x56\x9d\x80\xc3\x41\x4a\x8d\x08\x59\xdc\x65\xa4\x61\x28\xba\xb2\x7a\xf8\x7a\x71\x31\x4f\x31\x8c\x78\x2b\x23\xeb\xfe\x80\x8b\x82\xb0\xce\x26\x40\x1d\x2e\x22\xf0\x4d\x83\xd1\x25\x5d\xc5\x1a\xdd\xd3\xb7\x5a\x2b\x1a\xe0\x78\x45\x04\xdf\x54\x3a\xf8\x96\x9b\xe3\xea\x70\x82\xff\x7f\xc9\x88\x8c\x14\x4d\xa2\xaf\x58\x42\x9e\xc9\x60\x31\xdb\xca\xd3\xda\xd9\xaf\x0d\xcb\xaa\xaf\x26\x8c\xb8\xfc\xff\xea\xd9\x4f\x3c\x7c\xa4\x95\xe0\x56\xa9\xb4\x7a\xcd\xb7\x51\xfb\x73\xe6\x66\xc6\xc6\x55\xad\xe8\x29\x72\x97\xd0\x7a\xd1\xba\x5e\x43\xf1\xbc\xa3\x23\x01\x65\x13\x39\xe2\x29\x04\xcc\x8c\x42\xf5\x8c\x30\xc0\x4a\xaf\xdb\x03\x8d\xda\x08\x47\xdd\x98\x8d\xcd\xa6\xf3\xbf\xd1\x5c\x4b\x4c\x45\x25\x00\x4a\xa0\x6e\xef\xf8\xca\x61\x78\x3a\xac\xec\x57\xfb\x3d\x1f\x92\xb0\xfe\x2f\xd1\xa8\x5f\x67\x24\x51\x7b\x65\xe6\x14\xad\x68\x08\xd6\xf6\xee\x34\xdf\xf7\x31\x0f\xdc\x82\xae\xbf\xd9\x04\xb0\x1e\x1d\xc5\x4b\x29\x27\x09\x4b\x2d\xb6\x8d\x6f\x90\x3b\x68\x40\x1a\xde\xbf\x5a\x7e\x08\xd7\x8f\xf4\xef\x5d\x63\x65\x3a\x65\x04\x0c\xf9\xbf\xd4\xac\xa7\x98\x4a\x74\xd3\x71\x45\x98\x67\x80\xfc\x0b\x16\xac\x45\x16\x49\xde\x61\x88\xa7\xdb\xdf\x19\x1f\x64\xb5\xfc\x5e\x2a\xb4\x7b\x57\xf7\xf7\x27\x6c\xd4\x19\xc1\x7a\x3c\xa8\xe1\xb9\x39\xae\x49\xe4\x88\xac\xba\x6b\x96\x56\x10\xb5\x48\x01\x09\xc8\xb1\x7b\x80\xe1\xb7\xb7\x50\xdf\xc7\x59\x8d\x5d\x50\x11\xfd\x2d\xcc\x56\x00\xa3\x2e\xf5\xb5\x2a\x1e\xcc\x82\x0e\x30\x8a\xa3\x42\x72\x1a\xac\x09\x43\xbf\x66\x86\xb6\x4b\x25\x79\x37\x65\x04\xcc\xc4\x93\xd9\x7e\x6a\xed\x3f\xb0\xf9\xcd\x71\xa4\x3d\xd4\x97\xf0\x1f\x17\xc0\xe2\xcb\x37\x97\xaa\x2a\x2f\x25\x66\x56\x16\x8e\x6c\x49\x6a\xfc\x5f\xb9\x32\x46\xf6\xb1\x11\x63\x98\xa3\x46\xf1\xa6\x41\xf3\xb0\x41\xe9\x89\xf7\x91\x4f\x90\xcc\x2c\x7f\xff\x35\x78\x76\xe5\x06\xb5\x0d\x33\x4b\xa7\x7c\x22\x5b\xc3\x07\xba\x53\x71\x52\xf3\xf1\x61\x0e\x4e\xaf\xe5\x95\xf6\xd9\xd9\x0d\x11\xfa\xa9\x33\xa1\x5e\xf1\x36\x95\x46\x86\x8a\x7f\x3a\x45\xa9\x67\x68\xd4\x0f\xd9\xd0\x34\x12\xc0\x91\xc6\x31\x5c\xf4\xfd\xe7\xcb\x68\x60\x69\x37\x38\x0d\xb2\xea\xaa\x70\x7b\x4c\x41\x85\xc3\x2e\xdd\xcd\xd3\x06\x70\x5e\x4d\xc1\xff\xc8\x72\xee\xee\x47\x5a\x64\xdf\xac\x86\xab\xa4\x1c\x06\x18\x98\x3f\x87\x41\xc5\xef\x68\xd3\xa1\x01\xe8\xa3\xb8\xca\xc6\x0c\x90\x5c\x15\xfc\x91\x08\x40\xb9\x4c\x00\xa0\xb9\xd0",  # noqa E501
            "sig": b"\x0a\xab\x4c\x90\x05\x01\xb3\xe2\x4d\x7c\xdf\x46\x63\x32\x6a\x3a\x87\xdf\x5e\x48\x43\xb2\xcb\xdb\x67\xcb\xf6\xe4\x60\xfe\xc3\x50\xaa\x53\x71\xb1\x50\x8f\x9f\x45\x28\xec\xea\x23\xc4\x36\xd9\x4b\x5e\x8f\xcd\x4f\x68\x1e\x30\xa6\xac\x00\xa9\x70\x4a\x18\x8a\x03",  # noqa E501
        },
        {
            "key": b"\x83\x3f\xe6\x24\x09\x23\x7b\x9d\x62\xec\x77\x58\x75\x20\x91\x1e\x9a\x75\x9c\xec\x1d\x19\x75\x5b\x7d\xa9\x01\xb9\x6d\xca\x3d\x42",  # noqa E501
            "pubkey": b"\xec\x17\x2b\x93\xad\x5e\x56\x3b\xf4\x93\x2c\x70\xe1\x24\x50\x34\xc3\x54\x67\xef\x2e\xfd\x4d\x64\xeb\xf8\x19\x68\x34\x67\xe2\xbf",  # noqa E501
            "msg": b"\xdd\xaf\x35\xa1\x93\x61\x7a\xba\xcc\x41\x73\x49\xae\x20\x41\x31\x12\xe6\xfa\x4e\x89\xa9\x7e\xa2\x0a\x9e\xee\xe6\x4b\x55\xd3\x9a\x21\x92\x99\x2a\x27\x4f\xc1\xa8\x36\xba\x3c\x23\xa3\xfe\xeb\xbd\x45\x4d\x44\x23\x64\x3c\xe8\x0e\x2a\x9a\xc9\x4f\xa5\x4c\xa4\x9f",  # noqa E501
            "sig": b"\xdc\x2a\x44\x59\xe7\x36\x96\x33\xa5\x2b\x1b\xf2\x77\x83\x9a\x00\x20\x10\x09\xa3\xef\xbf\x3e\xcb\x69\xbe\xa2\x18\x6c\x26\xb5\x89\x09\x35\x1f\xc9\xac\x90\xb3\xec\xfd\xfb\xc7\xc6\x64\x31\xe0\x30\x3d\xca\x17\x9c\x13\x8a\xc1\x7a\xd9\xbe\xf1\x17\x73\x31\xa7\x04",  # noqa E501
        },
    ]

    def test_vectors(self):
        for v in self.vectors:
            key = load_ed25519_private_key(v["key"])
            k = AsymmetricKey.put(
                self.session, 0, "Test Ed25519", 0xFFFF, CAPABILITY.SIGN_EDDSA, key
            )
            self.assertEqual(
                serialize_ed25519_public_key(k.get_public_key()), v["pubkey"]
            )
            self.assertEqual(k.sign_eddsa(v["msg"]), v["sig"])
            k.delete()

    def test_generate_sign(self):
        key = AsymmetricKey.generate(
            self.session,
            0,
            "Test Ed25519",
            0xFFFF,
            CAPABILITY.SIGN_EDDSA,
            ALGORITHM.EC_ED25519,
        )
        pubkey = key.get_public_key()
        data = os.urandom(128)
        sig = key.sign_eddsa(data)
        pubkey.verify(sig, data)
        key.delete()

    def test_import_sign(self):
        s_key = ed25519.Ed25519PrivateKey.generate()
        v_key = s_key.public_key()
        key = AsymmetricKey.put(
            self.session, 0, "Test Ed25519", 0xFFFF, CAPABILITY.SIGN_EDDSA, s_key
        )
        data = os.urandom(129)
        sig = key.sign_eddsa(data)
        v_key.verify(sig, data)
        self.assertEqual(sig, s_key.sign(data))
        pub = key.get_public_key()
        self.assertEqual(
            v_key.public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            ),
            serialize_ed25519_public_key(pub),
        )
        key.delete()

    def test_generate_sign_long(self):
        key = AsymmetricKey.generate(
            self.session,
            0,
            "Test Ed25519",
            0xFFFF,
            CAPABILITY.SIGN_EDDSA,
            ALGORITHM.EC_ED25519,
        )
        pubkey = key.get_public_key()
        data = os.urandom(2019)
        sig = key.sign_eddsa(data)
        pubkey.verify(sig, data)
        key.delete()
