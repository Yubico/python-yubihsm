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
from yubihsm.defs import ALGORITHM, CAPABILITY, ERROR
from yubihsm.objects import AsymmetricKey
from yubihsm.exceptions import YubiHsmDeviceError

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.utils import int_from_bytes, int_to_bytes
from binascii import a2b_hex
import os


class TestRsaPkcs1v1_5(YubiHsmTestCase):

    def rsa_pkcs1v1_5_sign(self, keysize, hashtype):
        key = rsa.generate_private_key(
            public_exponent=0x10001,
            key_size=keysize,
            backend=default_backend())

        asymkey = AsymmetricKey.put(
            self.session, 0, 'RSA PKCS#1v1.5 Sign', 0xffff,
            CAPABILITY.SIGN_PKCS,
            key)

        data = os.urandom(64)
        resp = asymkey.sign_pkcs1v1_5(data, hash=hashtype)

        key.public_key().verify(
            resp,
            data,
            padding.PKCS1v15(),
            hashtype
        )

        asymkey.delete()

    def rsa_pkcs1v1_5_decrypt(self, keysize):
        key = rsa.generate_private_key(
            public_exponent=0x10001,
            key_size=keysize,
            backend=default_backend())

        asymkey = AsymmetricKey.put(
            self.session, 0, 'RSA PKCS#1v1.5 Decrypt', 0xffff,
            CAPABILITY.DECRYPT_PKCS,
            key)

        message = os.urandom(64)
        data = key.public_key().encrypt(message, padding.PKCS1v15())

        resp = asymkey.decrypt_pkcs1v1_5(data)
        self.assertEqual(message, resp)

        asymkey.delete()

    def test_rsa2048_pkcs1v1_5_sign(self):
        self.rsa_pkcs1v1_5_sign(2048, hashes.SHA256())
        self.rsa_pkcs1v1_5_sign(2048, hashes.SHA384())
        self.rsa_pkcs1v1_5_sign(2048, hashes.SHA512())

    def test_rsa3072_pkcs1v1_5_sign(self):
        self.rsa_pkcs1v1_5_sign(3072, hashes.SHA256())
        self.rsa_pkcs1v1_5_sign(3072, hashes.SHA384())
        self.rsa_pkcs1v1_5_sign(3072, hashes.SHA512())

    def test_rsa4096_pkcs1v1_5_sign(self):
        self.rsa_pkcs1v1_5_sign(4096, hashes.SHA256())
        self.rsa_pkcs1v1_5_sign(4096, hashes.SHA384())
        self.rsa_pkcs1v1_5_sign(4096, hashes.SHA512())

    def test_rsa2048_pkcs1v1_5_decrypt(self):
        self.rsa_pkcs1v1_5_decrypt(2048)

    def test_rsa3072_pkcs1v1_5_decrypt(self):
        self.rsa_pkcs1v1_5_decrypt(3072)

    def test_rsa4096_pkcs1v1_5_decrypt(self):
        self.rsa_pkcs1v1_5_decrypt(4096)

    def test_rsa_pkcs1_decrypt_errors(self):
        rawmessages = [
            # no actual padding bytes:
            b'\x00\x02\x00' + b'\xc3' * 236 + b'\x00',
            # first byte != 0x00:
            b'\x01\x02' + b'\xc3' * 237 + b'\x00',
            # second byte != 0x02:
            b'\x00\x01' + b'\xc3' * 237 + b'\x00',
            # only 7 bytes of padding:
            b'\x00\x02' + b'\xc3' * 7 + b'\x00' + b'\x3c' * 246
        ]

        rsakey = rsa.generate_private_key(
            public_exponent=0x10001,
            key_size=2048,
            backend=default_backend())

        key = AsymmetricKey.put(
            self.session, 0, 'pkcs1 test', 0xffff,
            CAPABILITY.DECRYPT_PKCS,
            rsakey)

        numbers = key.get_public_key().public_numbers()

        for m in rawmessages:
            error = ERROR.OK
            m = m.ljust(256, b'\xc3')
            m_int = int_from_bytes(m, 'big')
            enc = pow(m_int, numbers.e, numbers.n)
            try:
                key.decrypt_pkcs1v1_5(int_to_bytes(enc).rjust(256, b'\x00'))
            except YubiHsmDeviceError as e:
                error = e.code
            self.assertEqual(error, ERROR.INVALID_DATA)

        key.delete()


class TestRsaPss_Sign(YubiHsmTestCase):

    def rsa_pss_sign(self, keysize, hashtype, mgf1hash=None):
        if mgf1hash is None:
            mgf1hash = hashtype

        key = rsa.generate_private_key(
            public_exponent=0x10001,
            key_size=keysize,
            backend=default_backend())

        asymkey = AsymmetricKey.put(
            self.session, 0, 'RSA PSS Sign', 0xffff, CAPABILITY.SIGN_PSS, key)

        # No salt
        data = os.urandom(64)
        resp = asymkey.sign_pss(data, 0, hash=hashtype, mgf_hash=mgf1hash)

        key.public_key().verify(
            resp,
            data,
            padding.PSS(padding.MGF1(mgf1hash), 0),
            hashtype
        )

        # Max - len salt
        saltlen = keysize // 8 - hashtype.digest_size - 2
        data = os.urandom(64)
        resp = asymkey.sign_pss(data, saltlen, hash=hashtype,
                                mgf_hash=mgf1hash)

        key.public_key().verify(
            resp,
            data,
            padding.PSS(
                padding.MGF1(mgf1hash),
                padding.PSS.MAX_LENGTH),
            hashtype)

        asymkey.delete()

    def test_rsa2048_pss_sign(self):
        self.rsa_pss_sign(2048, hashes.SHA256())
        self.rsa_pss_sign(2048, hashes.SHA384())
        self.rsa_pss_sign(2048, hashes.SHA512())

        self.rsa_pss_sign(2048, hashes.SHA256(), hashes.SHA1())

    def test_rsa3072_pss_sign(self):
        self.rsa_pss_sign(3072, hashes.SHA256())
        self.rsa_pss_sign(3072, hashes.SHA384())
        self.rsa_pss_sign(3072, hashes.SHA512())

        self.rsa_pss_sign(3072, hashes.SHA256(), hashes.SHA1())

    def test_rsa4096_pss_sign(self):
        self.rsa_pss_sign(4096, hashes.SHA256())
        self.rsa_pss_sign(4096, hashes.SHA384())
        self.rsa_pss_sign(4096, hashes.SHA512())

        self.rsa_pss_sign(4096, hashes.SHA256(), hashes.SHA1())


class TestRsa(YubiHsmTestCase):

    def generate_rsa_sign(self, algo):
        asymkey = AsymmetricKey.generate(
            self.session, 0, 'Generate RSA Sign', 0xffff,
            CAPABILITY.SIGN_PKCS,
            algo)

        pub = asymkey.get_public_key()

        data = os.urandom(64)
        resp = asymkey.sign_pkcs1v1_5(data)

        pub.verify(resp, data, padding.PKCS1v15(), hashes.SHA256())

        asymkey.delete()

    def test_generate_rsa2048_sign(self):
        self.generate_rsa_sign(ALGORITHM.RSA_2048)

    def test_generate_rsa3072_sign(self):
        self.generate_rsa_sign(ALGORITHM.RSA_3072)

    def test_generate_rsa4096_sign(self):
        self.generate_rsa_sign(ALGORITHM.RSA_4096)


class TestRsaPubkey(YubiHsmTestCase):

    def pubkey_rsa(self, keysize):
        key = rsa.generate_private_key(
            public_exponent=0x10001,
            key_size=keysize,
            backend=default_backend())

        asymkey = AsymmetricKey.put(
            self.session, 0, 'Pubkey RSA', 0xffff, CAPABILITY.SIGN_PKCS, key)

        pub = asymkey.get_public_key()
        self.assertEqual(
            pub.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo),
            key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo))

        data = os.urandom(64)
        resp = asymkey.sign_pkcs1v1_5(data)

        pub.verify(resp, data, padding.PKCS1v15(), hashes.SHA256())

        asymkey.delete()

    def test_pubkey_rsa(self):
        self.pubkey_rsa(2048)
        self.pubkey_rsa(3072)
        self.pubkey_rsa(4096)


class TestOaep(YubiHsmTestCase):

    p = 0xecf5aecd1e5515fffacbd75a2816c6ebf49018cdfb4638e185d66a7396b6f8090f8018c7fd95cc34b857dc17f0cc6516bb1346ab4d582cadad7b4103352387b70338d084047c9d9539b6496204b3dd6ea442499207bec01f964287ff6336c3984658336846f56e46861881c10233d2176bf15a5e96ddc780bc868aa77d3ce769  # noqa: E501
    q = 0xbc46c464fc6ac4ca783b0eb08a3c841b772f7e9b2f28babd588ae885e1a0c61e4858a0fb25ac299990f35be85164c259ba1175cdd7192707135184992b6c29b746dd0d2cabe142835f7d148cc161524b4a09946d48b828473f1ce76b6cb6886c345c03e05f41d51b5c3a90a3f24073c7d74a4fe25d9cf21c75960f3fc3863183  # noqa: E501
    d = 0x056b04216fe5f354ac77250a4b6b0c8525a85c59b0bd80c56450a22d5f438e596a333aa875e291dd43f48cb88b9d5fc0d499f9fcd1c397f9afc070cd9e398c8d19e61db7c7410a6b2675dfbf5d345b804d201add502d5ce2dfcb091ce9997bbebe57306f383e4d588103f036f7e85d1934d152a323e4a8db451d6f4a5b1b0f102cc150e02feee2b88dea4ad4c1baccb24d84072d14e1d24a6771f7408ee30564fb86d4393a34bcf0b788501d193303f13a2284b001f0f649eaf79328d4ac5c430ab4414920a9460ed1b7bc40ec653e876d09abc509ae45b525190116a0c26101848298509c1c3bf3a483e7274054e15e97075036e989f60932807b5257751e79  # noqa: E501
    dp1 = 0xc73564571d00fb15d08a3de9957a50915d7126e9442dacf42bc82e862e5673ff6a008ed4d2e374617df89f17a160b43b7fda9cb6b6b74218609815f7d45ca263c159aa32d272d127faf4bc8ca2d77378e8aeb19b0ad7da3cb3de0ae7314980f62b6d4b0a875d1df03c1bae39ccd833ef6cd7e2d9528bf084d1f969e794e9f6c1  # noqa: E501
    dq1 = 0x2658b37f6df9c1030be1db68117fa9d87e39ea2b693b7e6d3a2f70947413eec6142e18fb8dfcb6ac545d7c86a0ad48f8457170f0efb26bc48126c53efd1d16920198dc2a1107dc282db6a80cd3062360ba3fa13f70e4312ff1a6cd6b8fc4cd9c5c3db17c6d6a57212f73ae29f619327bad59b153858585ba4e28b60a62a45e49  # noqa: E501
    qinv = 0x6f38526b3925085534ef3e415a836ede8b86158a2c7cbfeccb0bd834304fec683ba8d4f479c433d43416e63269623cea100776d85aff401d3fff610ee65411ce3b1363d63a9709eede42647cea561493d54570a879c18682cd97710b96205ec31117d73b5f36223fadd6e8ba90dd7c0ee61d44e163251e20c7f66eb305117cb8  # noqa: E501
    e = 0x10001
    n = 0xae45ed5601cec6b8cc05f803935c674ddbe0d75c4c09fd7951fc6b0caec313a8df39970c518bffba5ed68f3f0d7f22a4029d413f1ae07e4ebe9e4177ce23e7f5404b569e4ee1bdcf3c1fb03ef113802d4f855eb9b5134b5a7c8085adcae6fa2fa1417ec3763be171b0c62b760ede23c12ad92b980884c641f5a8fac26bdad4a03381a22fe1b754885094c82506d4019a535a286afeb271bb9ba592de18dcf600c2aeeae56e02f7cf79fc14cf3bdc7cd84febbbf950ca90304b2219a7aa063aefa2c3c1980e560cd64afe779585b6107657b957857efde6010988ab7de417fc88d8f384c4e6e72c3f943e0c31c0c4a5cc36f879d8a3ac9d7d59860eaada6b83bb  # noqa: E501

    vectors = [
        {'msg': b'\x8b\xba\x6b\xf8\x2a\x6c\x0f\x86\xd5\xf1\x75\x6e\x97\x95\x68\x70\xb0\x89\x53\xb0\x6b\x4e\xb2\x05\xbc\x16\x94\xee', 'enc': b'\x53\xea\x5d\xc0\x8c\xd2\x60\xfb\x3b\x85\x85\x67\x28\x7f\xa9\x15\x52\xc3\x0b\x2f\xeb\xfb\xa2\x13\xf0\xae\x87\x70\x2d\x06\x8d\x19\xba\xb0\x7f\xe5\x74\x52\x3d\xfb\x42\x13\x9d\x68\xc3\xc5\xaf\xee\xe0\xbf\xe4\xcb\x79\x69\xcb\xf3\x82\xb8\x04\xd6\xe6\x13\x96\x14\x4e\x2d\x0e\x60\x74\x1f\x89\x93\xc3\x01\x4b\x58\xb9\xb1\x95\x7a\x8b\xab\xcd\x23\xaf\x85\x4f\x4c\x35\x6f\xb1\x66\x2a\xa7\x2b\xfc\xc7\xe5\x86\x55\x9d\xc4\x28\x0d\x16\x0c\x12\x67\x85\xa7\x23\xeb\xee\xbe\xff\x71\xf1\x15\x94\x44\x0a\xae\xf8\x7d\x10\x79\x3a\x87\x74\xa2\x39\xd4\xa0\x4c\x87\xfe\x14\x67\xb9\xda\xf8\x52\x08\xec\x6c\x72\x55\x79\x4a\x96\xcc\x29\x14\x2f\x9a\x8b\xd4\x18\xe3\xc1\xfd\x67\x34\x4b\x0c\xd0\x82\x9d\xf3\xb2\xbe\xc6\x02\x53\x19\x62\x93\xc6\xb3\x4d\x3f\x75\xd3\x2f\x21\x3d\xd4\x5c\x62\x73\xd5\x05\xad\xf4\xcc\xed\x10\x57\xcb\x75\x8f\xc2\x6a\xee\xfa\x44\x12\x55\xed\x4e\x64\xc1\x99\xee\x07\x5e\x7f\x16\x64\x61\x82\xfd\xb4\x64\x73\x9b\x68\xab\x5d\xaf\xf0\xe6\x3e\x95\x52\x01\x68\x24\xf0\x54\xbf\x4d\x3c\x8c\x90\xa9\x7b\xb6\xb6\x55\x32\x84\xeb\x42\x9f\xcc'},  # noqa: E501
        {'msg': b'\xe6\xad\x18\x1f\x05\x3b\x58\xa9\x04\xf2\x45\x75\x10\x37\x3e\x57', 'enc': b'\xa2\xb1\xa4\x30\xa9\xd6\x57\xe2\xfa\x1c\x2b\xb5\xed\x43\xff\xb2\x5c\x05\xa3\x08\xfe\x90\x93\xc0\x10\x31\x79\x5f\x58\x74\x40\x01\x10\x82\x8a\xe5\x8f\xb9\xb5\x81\xce\x9d\xdd\xd3\xe5\x49\xae\x04\xa0\x98\x54\x59\xbd\xe6\xc6\x26\x59\x4e\x7b\x05\xdc\x42\x78\xb2\xa1\x46\x5c\x13\x68\x40\x88\x23\xc8\x5e\x96\xdc\x66\xc3\xa3\x09\x83\xc6\x39\x66\x4f\xc4\x56\x9a\x37\xfe\x21\xe5\xa1\x95\xb5\x77\x6e\xed\x2d\xf8\xd8\xd3\x61\xaf\x68\x6e\x75\x02\x29\xbb\xd6\x63\xf1\x61\x86\x8a\x50\x61\x5e\x0c\x33\x7b\xec\x0c\xa3\x5f\xec\x0b\xb1\x9c\x36\xeb\x2e\x0b\xbc\xc0\x58\x2f\xa1\xd9\x3a\xac\xdb\x06\x10\x63\xf5\x9f\x2c\xe1\xee\x43\x60\x5e\x5d\x89\xec\xa1\x83\xd2\xac\xdf\xe9\xf8\x10\x11\x02\x2a\xd3\xb4\x3a\x3d\xd4\x17\xda\xc9\x4b\x4e\x11\xea\x81\xb1\x92\x96\x6e\x96\x6b\x18\x20\x82\xe7\x19\x64\x60\x7b\x4f\x80\x02\xf3\x62\x99\x84\x4a\x11\xf2\xae\x0f\xae\xac\x2e\xae\x70\xf8\xf4\xf9\x80\x88\xac\xdc\xd0\xac\x55\x6e\x9f\xcc\xc5\x11\x52\x19\x08\xfa\xd2\x6f\x04\xc6\x42\x01\x45\x03\x05\x77\x87\x58\xb0\x53\x8b\xf8\xb5\xbb\x14\x4a\x82\x8e\x62\x97\x95'},  # noqa: E501
        {'msg': b'\x51\x0a\x2c\xf6\x0e\x86\x6f\xa2\x34\x05\x53\xc9\x4e\xa3\x9f\xbc\x25\x63\x11\xe8\x3e\x94\x45\x4b\x41\x24', 'enc': b'\x98\x86\xc3\xe6\x76\x4a\x8b\x9a\x84\xe8\x41\x48\xeb\xd8\xc3\xb1\xaa\x80\x50\x38\x1a\x78\xf6\x68\x71\x4c\x16\xd9\xcf\xd2\xa6\xed\xc5\x69\x79\xc5\x35\xd9\xde\xe3\xb4\x4b\x85\xc1\x8b\xe8\x92\x89\x92\x37\x17\x11\x47\x22\x16\xd9\x5d\xda\x98\xd2\xee\x83\x47\xc9\xb1\x4d\xff\xdf\xf8\x4a\xa4\x8d\x25\xac\x06\xf7\xd7\xe6\x53\x98\xac\x96\x7b\x1c\xe9\x09\x25\xf6\x7d\xce\x04\x9b\x7f\x81\x2d\xb0\x74\x29\x97\xa7\x4d\x44\xfe\x81\xdb\xe0\xe7\xa3\xfe\xaf\x2e\x5c\x40\xaf\x88\x8d\x55\x0d\xdb\xbe\x3b\xc2\x06\x57\xa2\x95\x43\xf8\xfc\x29\x13\xb9\xbd\x1a\x61\xb2\xab\x22\x56\xec\x40\x9b\xbd\x7d\xc0\xd1\x77\x17\xea\x25\xc4\x3f\x42\xed\x27\xdf\x87\x38\xbf\x4a\xfc\x67\x66\xff\x7a\xff\x08\x59\x55\x5e\xe2\x83\x92\x0f\x4c\x8a\x63\xc4\xa7\x34\x0c\xba\xfd\xdc\x33\x9e\xcd\xb4\xb0\x51\x50\x02\xf9\x6c\x93\x2b\x5b\x79\x16\x7a\xf6\x99\xc0\xad\x3f\xcc\xfd\xf0\xf4\x4e\x85\xa7\x02\x62\xbf\x2e\x18\xfe\x34\xb8\x50\x58\x99\x75\xe8\x67\xff\x96\x9d\x48\xea\xbf\x21\x22\x71\x54\x6c\xdc\x05\xa6\x9e\xcb\x52\x6e\x52\x87\x0c\x83\x6f\x30\x7b\xd7\x98\x78\x0e\xde'},  # noqa: E501
        {'msg': b'\xbc\xdd\x19\x0d\xa3\xb7\xd3\x00\xdf\x9a\x06\xe2\x2c\xaa\xe2\xa7\x5f\x10\xc9\x1f\xf6\x67\xb7\xc1\x6b\xde\x8b\x53\x06\x4a\x26\x49\xa9\x40\x45\xc9', 'enc': b'\x63\x18\xe9\xfb\x5c\x0d\x05\xe5\x30\x7e\x16\x83\x43\x6e\x90\x32\x93\xac\x46\x42\x35\x8a\xaa\x22\x3d\x71\x63\x01\x3a\xba\x87\xe2\xdf\xda\x8e\x60\xc6\x86\x0e\x29\xa1\xe9\x26\x86\x16\x3e\xa0\xb9\x17\x5f\x32\x9c\xa3\xb1\x31\xa1\xed\xd3\xa7\x77\x59\xa8\xb9\x7b\xad\x6a\x4f\x8f\x43\x96\xf2\x8c\xf6\xf3\x9c\xa5\x81\x12\xe4\x81\x60\xd6\xe2\x03\xda\xa5\x85\x6f\x3a\xca\x5f\xfe\xd5\x77\xaf\x49\x94\x08\xe3\xdf\xd2\x33\xe3\xe6\x04\xdb\xe3\x4a\x9c\x4c\x90\x82\xde\x65\x52\x7c\xac\x63\x31\xd2\x9d\xc8\x0e\x05\x08\xa0\xfa\x71\x22\xe7\xf3\x29\xf6\xcc\xa5\xcf\xa3\x4d\x4d\x1d\xa4\x17\x80\x54\x57\xe0\x08\xbe\xc5\x49\xe4\x78\xff\x9e\x12\xa7\x63\xc4\x77\xd1\x5b\xbb\x78\xf5\xb6\x9b\xd5\x78\x30\xfc\x2c\x4e\xd6\x86\xd7\x9b\xc7\x2a\x95\xd8\x5f\x88\x13\x4c\x6b\x0a\xfe\x56\xa8\xcc\xfb\xc8\x55\x82\x8b\xb3\x39\xbd\x17\x90\x9c\xf1\xd7\x0d\xe3\x33\x5a\xe0\x70\x39\x09\x3e\x60\x6d\x65\x53\x65\xde\x65\x50\xb8\x72\xcd\x6d\xe1\xd4\x40\xee\x03\x1b\x61\x94\x5f\x62\x9a\xd8\xa3\x53\xb0\xd4\x09\x39\xe9\x6a\x3c\x45\x0d\x2a\x8d\x5e\xee\x9f\x67\x80\x93\xc8'},  # noqa: E501
        {'msg': b'\xa7\xdd\x6c\x7d\xc2\x4b\x46\xf9\xdd\x5f\x1e\x91\xad\xa4\xc3\xb3\xdf\x94\x7e\x87\x72\x32\xa9', 'enc': b'\x75\x29\x08\x72\xcc\xfd\x4a\x45\x05\x66\x0d\x65\x1f\x56\xda\x6d\xaa\x09\xca\x13\x01\xd8\x90\x63\x2f\x6a\x99\x2f\x3d\x56\x5c\xee\x46\x4a\xfd\xed\x40\xed\x3b\x5b\xe9\x35\x67\x14\xea\x5a\xa7\x65\x5f\x4a\x13\x66\xc2\xf1\x7c\x72\x8f\x6f\x2c\x5a\x5d\x1f\x8e\x28\x42\x9b\xc4\xe6\xf8\xf2\xcf\xf8\xda\x8d\xc0\xe0\xa9\x80\x8e\x45\xfd\x09\xea\x2f\xa4\x0c\xb2\xb6\xce\x6f\xff\xf5\xc0\xe1\x59\xd1\x1b\x68\xd9\x0a\x85\xf7\xb8\x4e\x10\x3b\x09\xe6\x82\x66\x64\x80\xc6\x57\x50\x5c\x09\x29\x25\x94\x68\xa3\x14\x78\x6d\x74\xea\xb1\x31\x57\x3c\xf2\x34\xbf\x57\xdb\x7d\x9e\x66\xcc\x67\x48\x19\x2e\x00\x2d\xc0\xde\xea\x93\x05\x85\xf0\x83\x1f\xdc\xd9\xbc\x33\xd5\x1f\x79\xed\x2f\xfc\x16\xbc\xf4\xd5\x98\x12\xfc\xeb\xca\xa3\xf9\x06\x9b\x0e\x44\x56\x86\xd6\x44\xc2\x5c\xcf\x63\xb4\x56\xee\x5f\xa6\xff\xe9\x6f\x19\xcd\xf7\x51\xfe\xd9\xea\xf3\x59\x57\x75\x4d\xbf\x4b\xfe\xa5\x21\x6a\xa1\x84\x4d\xc5\x07\xcb\x2d\x08\x0e\x72\x2e\xba\x15\x03\x08\xc2\xb5\xff\x11\x93\x62\x0f\x17\x66\xec\xf4\x48\x1b\xaf\xb9\x43\xbd\x29\x28\x77\xf2\x13\x6c\xa4\x94\xab\xa0'},  # noqa: E501
        {'msg': b'\xea\xf1\xa7\x3a\x1b\x0c\x46\x09\x53\x7d\xe6\x9c\xd9\x22\x8b\xbc\xfb\x9a\x8c\xa8\xc6\xc3\xef\xaf\x05\x6f\xe4\xa7\xf4\x63\x4e\xd0\x0b\x7c\x39\xec\x69\x22\xd7\xb8\xea\x2c\x04\xeb\xac', 'enc': b'\x2d\x20\x7a\x73\x43\x2a\x8f\xb4\xc0\x30\x51\xb3\xf7\x3b\x28\xa6\x17\x64\x09\x8d\xfa\x34\xc4\x7a\x20\x99\x5f\x81\x15\xaa\x68\x16\x67\x9b\x55\x7e\x82\xdb\xee\x58\x49\x08\xc6\xe6\x97\x82\xd7\xde\xb3\x4d\xbd\x65\xaf\x06\x3d\x57\xfc\xa7\x6a\x5f\xd0\x69\x49\x2f\xd6\x06\x8d\x99\x84\xd2\x09\x35\x05\x65\xa6\x2e\x5c\x77\xf2\x30\x38\xc1\x2c\xb1\x0c\x66\x34\x70\x9b\x54\x7c\x46\xf6\xb4\xa7\x09\xbd\x85\xca\x12\x2d\x74\x46\x5e\xf9\x77\x62\xc2\x97\x63\xe0\x6d\xbc\x7a\x9e\x73\x8c\x78\xbf\xca\x01\x02\xdc\x5e\x79\xd6\x5b\x97\x3f\x28\x24\x0c\xaa\xb2\xe1\x61\xa7\x8b\x57\xd2\x62\x45\x7e\xd8\x19\x5d\x53\xe3\xc7\xae\x9d\xa0\x21\x88\x3c\x6d\xb7\xc2\x4a\xfd\xd2\x32\x2e\xac\x97\x2a\xd3\xc3\x54\xc5\xfc\xef\x1e\x14\x6c\x3a\x02\x90\xfb\x67\xad\xf0\x07\x06\x6e\x00\x42\x8d\x2c\xec\x18\xce\x58\xf9\x32\x86\x98\xde\xfe\xf4\xb2\xeb\x5e\xc7\x69\x18\xfd\xe1\xc1\x98\xcb\xb3\x8b\x7a\xfc\x67\x62\x6a\x9a\xef\xec\x43\x22\xbf\xd9\x0d\x25\x63\x48\x1c\x9a\x22\x1f\x78\xc8\x27\x2c\x82\xd1\xb6\x2a\xb9\x14\xe1\xc6\x9f\x6a\xf6\xef\x30\xca\x52\x60\xdb\x4a\x46'},  # noqa: E501
    ]

    def oaep_vectors(self, Venc, Vmsg):
        pubnum = rsa.RSAPublicNumbers(n=self.n, e=self.e)
        key = rsa.RSAPrivateNumbers(
            p=self.p,
            q=self.q,
            d=self.d,
            dmp1=self.dp1,
            dmq1=self.dq1,
            iqmp=self.qinv,
            public_numbers=pubnum).private_key(default_backend())

        asymkey = AsymmetricKey.put(
            self.session, 0, 'OAEP Vectors', 0xffff,
            CAPABILITY.DECRYPT_OAEP,
            key)

        dec = asymkey.decrypt_oaep(Venc, hash=hashes.SHA1(),
                                   mgf_hash=hashes.SHA1())
        self.assertEqual(Vmsg, dec)

        asymkey.delete()

    def oaep_rsa_decrypt(self, keylength, hashtype, mgf1hash=None):
        if mgf1hash is None:
            mgf1hash = hashtype

        key = rsa.generate_private_key(
            public_exponent=0x10001,
            key_size=keylength,
            backend=default_backend())

        asymkey = AsymmetricKey.put(
            self.session, 0, 'OAEP RSA Decrypt', 0xffff,
            CAPABILITY.DECRYPT_OAEP,
            key)

        data = os.urandom(64)
        ciphertext = key.public_key().encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=mgf1hash),
                algorithm=hashtype,
                label=None))

        dec = asymkey.decrypt_oaep(ciphertext, hash=hashtype,
                                   mgf_hash=mgf1hash)
        self.assertEqual(data, dec)

        asymkey.delete()

    def test_oaep_double0(self):
        data = a2b_hex('77294f3a4f5cfc921d9255a6895f8d2397e7d312e1b10b41c88b025748f0b6d4c41c4bdc6309388648a3b7a07112a11f831d9d6e1af1408fae875be2868bc4d0')  # noqa
        # this ciphertext is special as it decrypts to a valid plaintext
        # starting with 0000
        ciphertext = a2b_hex('add1fd0bc2e9439a76c53fa4655e4bef77394dee407903604d665ba0e506334ddffc689e3bec658fc15c80c70ffddb8a8ce578d441926106316067a8c5e8b5f2655d035eff1525cf697720baf510af722d14539ccaf605785a9f4cfd284e4b496c54684a0c72fae522be186aedcedf47da63408065345180e30d7cb003cd64b5ce508ea029999ad695f1f2464fb659db5c2779631f1c27d650bc8b7ae23048b8dc1d51ad9623a4af0f7363f74eed0e16d947322d1a3a76ef8dbdf9c0258f393c0f2d7ebaccfcc116f759f0e9077387de74b1cb82851e1ded0128e48bbde389bd407cf8339752b9c070bf22ad64eaa12ee996f474a6412f7642aa0fa66873b5d2')  # noqa

        h = hashes.SHA1()
        rsapem = b"""
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA7mKlVPrZdxLkYrfGESb3KI4UbWKaKOfX49LqZ2pUypF13VRi
yqfpBbjAJztEy8BvOgbIEJgDtRVyUHCO+pfs6uVakYEcbLZzP92iZaFTwa9//B+P
Hq+vtNejdO5Zsqd1s11bCPy6vpPXeMPbbT5s9gR7ENGdNwUkusVRtQweJAd5icVU
edewI/4npIZG7To0iKUS4OvuqKWi/ms9fpi5l5BeJkok+5P7nQlmE5H5P+MuHUaC
KHPdzbfaqIYof11XhsUYzgvEZnhz/YPwDiMiLXpZD0kT7azZWjz38rmWCz0tdh7a
Cs/Lu1n17KrtT62kXYeO1Ni5Osy43xEHcqp5WQIDAQABAoIBAHrv+J+4tknIPmwC
pmzWEYSisTowLZyG5Dmj3irzFUNafNRl3oTwzyWaP857rGD/ntzn/mlAXDkZFFkT
k0j87Lu/CFQdp5ERDqKTJFsRNeafIXvesqp6pDy5MJzvBucxoWuc64PZAl2iVO78
4r6WAQ9nBCiKUW+8gVKozBh4ZVriWRYhe1JD06OVrOxws2Aql8/3BooO14f0DeSe
6tgn49d3c6/lrFe/vB+46kDg4FNxeTozGgIcI6siVAFEaJkBU629SEGLJW1O1Zcx
tL41xK27S/BW47sSE91D7TT/0DYH7c1KNNx4IRx8B+AHo/lkyCawVUVmeYPrjC90
oGe27gECgYEA/Pkk9p0+t9ir6gUibkh1XoAVzryPnMCeCXenpTvFKjfOXdr5Sy2w
ZSYGJXcUm82G0XRB+WWyTtFvPUYCt7gJ3ncqrVSAa2LhgWowk0CpyOtm6isrRWrh
3wXj4mRzZuIe0XNnS/4gb/1+8I826r4CwOWrxUASP8bYTLB9nkglK/kCgYEA8TzR
np/2lyJVbuqAMOymel0ZUEh+yWEOif5nQGely6QVmUmAuCH+pP8pmCCreAuu/mQ9
U1obXMmr5D0rH7jA4z8DAeGXSvPVN7MJlpS1HoPGzDnKuuDad8/rJUXyKOACYXw5
xeXtQnf+5AHC0G8IFmru1G4C6UsyRkG/gpVPUGECgYEA7OxeXQZKTh8Ea2mhpI4C
Np5ZTkU1b4bKvG0vOsZu0ypvAWHrJyjEUwc4rHAJgh4MTTDH9U70n3Lw7v8Z3nzj
6VHMS4efunNiZjVRByiBm2Y0/c2uehYvMxQuKMMRfeL7IAkoTnjUYm6VK7HFqjaJ
F6ZCqLtoHAkcXT7Sd6J0BekCgYEAy1Lshprils2MXljtxM6hHj87p6wCmK7iNzKi
SelSF0psHe+Sux+D5gNeRmc6vopyat2HxqoKp/EenNdlcm4gvSgN29cM0lKjYjfX
nAAoi9ibhOQs18fOuu8WjSrgCM2NlCbE9uRtTfmfbwOA9HawxVxJgehbMdB8RjUC
OgioeeECgYBpGDz7CkblZQl8YXcOqFh9Y40ePG467gIaEesbiOIUVsN/J9Vkdy/U
qMS+DogAW9kGj5MA/L1EQxpsZDRZSH15AM1FXeX5cjItOWkg5LzfTwqA29xaIC97
4ddiJOH50Tqy7YRs40IxF+995AgMq4PvP1K+SlV4hQ6W17JsT2UsBg==
-----END RSA PRIVATE KEY-----
"""
        key = serialization.load_pem_private_key(
            rsapem, password=None, backend=default_backend())
        asymkey = AsymmetricKey.put(
            self.session, 0, 'OAEP RSA Decrypt', 0xffff, CAPABILITY.ALL, key)

        plain = key.decrypt(
            ciphertext,
            padding.OAEP(mgf=padding.MGF1(algorithm=h), algorithm=h, label=None)
        )

        self.assertEqual(plain, data)
        dec = asymkey.decrypt_oaep(ciphertext, hash=h, mgf_hash=h)
        self.assertEqual(dec, data)
        asymkey.delete()

    def test_oaep_vectors(self):
        for v in self.vectors:
            self.oaep_vectors(v['enc'], v['msg'])

    def test_rsa2048_oaep_decrypt(self):
        self.oaep_rsa_decrypt(2048, hashes.SHA1())
        self.oaep_rsa_decrypt(2048, hashes.SHA256())
        self.oaep_rsa_decrypt(2048, hashes.SHA384())
        self.oaep_rsa_decrypt(2048, hashes.SHA512())

        self.oaep_rsa_decrypt(2048, hashes.SHA256(), hashes.SHA1())

    def test_rsa3072_oaep_decrypt(self):
        self.oaep_rsa_decrypt(3072, hashes.SHA1())
        self.oaep_rsa_decrypt(3072, hashes.SHA256())
        self.oaep_rsa_decrypt(3072, hashes.SHA384())
        self.oaep_rsa_decrypt(3072, hashes.SHA512())

        self.oaep_rsa_decrypt(3072, hashes.SHA256(), hashes.SHA1())

    def test_rsa4096_oaep_decrypt(self):
        self.oaep_rsa_decrypt(4096, hashes.SHA1())
        self.oaep_rsa_decrypt(4096, hashes.SHA256())
        self.oaep_rsa_decrypt(4096, hashes.SHA384())
        self.oaep_rsa_decrypt(4096, hashes.SHA512())

        self.oaep_rsa_decrypt(4096, hashes.SHA256(), hashes.SHA1())
