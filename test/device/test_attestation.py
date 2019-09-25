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
from yubihsm.defs import ALGORITHM, CAPABILITY
from yubihsm.objects import AsymmetricKey
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.hazmat.primitives.serialization import Encoding
import datetime
import uuid


class TestAttestation(YubiHsmTestCase):
    def create_pair(self, algorithm):
        if algorithm == ALGORITHM.RSA_2048:
            private_key = rsa.generate_private_key(0x10001, 2048, default_backend())
        elif algorithm == ALGORITHM.RSA_3072:
            private_key = rsa.generate_private_key(0x10001, 3072, default_backend())
        elif algorithm == ALGORITHM.RSA_4096:
            private_key = rsa.generate_private_key(0x10001, 4096, default_backend())
        else:
            ec_curve = ALGORITHM.to_curve(algorithm)
            private_key = ec.generate_private_key(ec_curve, default_backend())

        builder = x509.CertificateBuilder()
        name = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, u"Test Attestation Certificate")]
        )
        builder = builder.subject_name(name)
        builder = builder.issuer_name(name)
        one_day = datetime.timedelta(1, 0, 0)
        builder = builder.not_valid_before(datetime.datetime.today() - one_day)
        builder = builder.not_valid_after(datetime.datetime.today() + one_day)
        builder = builder.serial_number(int(uuid.uuid4()))
        builder = builder.public_key(private_key.public_key())
        certificate = builder.sign(private_key, hashes.SHA256(), default_backend())

        attkey = AsymmetricKey.put(
            self.session,
            0,
            "Test Create Pair",
            0xFFFF,
            CAPABILITY.SIGN_ATTESTATION_CERTIFICATE,
            private_key,
        )

        certobj = attkey.put_certificate(
            "Test Create Pair", 0xFFFF, CAPABILITY.NONE, certificate
        )

        self.assertEqual(certificate.public_bytes(Encoding.DER), certobj.get())
        return attkey, certobj, certificate

    def test_attestation(self):
        algs = [
            ALGORITHM.RSA_2048,
            ALGORITHM.RSA_3072,
            ALGORITHM.RSA_4096,
            ALGORITHM.EC_P256,
            ALGORITHM.EC_P384,
            ALGORITHM.EC_P521,
            ALGORITHM.EC_K256,
            ALGORITHM.EC_P224,
        ]

        keys = [
            AsymmetricKey.generate(
                self.session, 0, "Test Attestation %x" % algo, 0xFFFF, 0, algo
            )
            for algo in algs
        ]

        for algo in algs:
            attkey, attcertobj, attcert = self.create_pair(algo)
            pubkey = attcert.public_key()

            for key in keys:
                cert = key.attest(attkey.id)
                data = cert.tbs_certificate_bytes
                if isinstance(pubkey, rsa.RSAPublicKey):
                    pubkey.verify(
                        cert.signature,
                        data,
                        padding.PKCS1v15(),
                        cert.signature_hash_algorithm,
                    )
                else:
                    pubkey.verify(
                        cert.signature, data, ec.ECDSA(cert.signature_hash_algorithm)
                    )

            attkey.delete()
            attcertobj.delete()

        for key in keys:
            key.delete()
