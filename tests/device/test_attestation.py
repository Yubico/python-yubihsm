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

from yubihsm.defs import ALGORITHM, CAPABILITY, FIPS_STATUS, OBJECT
from yubihsm.objects import AsymmetricKey, AttestationExtensions
from yubihsm.exceptions import YubiHsmDeviceError
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.hazmat.primitives.serialization import Encoding
from time import sleep
import datetime
import uuid
import pytest


def create_pair(session, algorithm):
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
        [x509.NameAttribute(NameOID.COMMON_NAME, "Test Attestation Certificate")]
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
        session,
        0,
        "Test Create Pair",
        0xFFFF,
        CAPABILITY.SIGN_ATTESTATION_CERTIFICATE,
        private_key,
    )

    certobj = attkey.put_certificate(
        "Test Create Pair", 0xFFFF, CAPABILITY.NONE, certificate
    )

    assert certificate.public_bytes(Encoding.DER) == certobj.get()
    return attkey, certobj, certificate


ASYM_ALGOS = [
    ALGORITHM.RSA_2048,
    ALGORITHM.RSA_3072,
    ALGORITHM.RSA_4096,
    ALGORITHM.EC_P256,
    ALGORITHM.EC_P384,
    ALGORITHM.EC_P521,
    ALGORITHM.EC_K256,
    ALGORITHM.EC_P224,
]


class TestAttestationAlgorithms:
    @pytest.fixture(scope="class", params=ASYM_ALGOS)
    def generated_key(self, request, session):
        algorithm = request.param
        key = AsymmetricKey.generate(
            session,
            0,
            "Test Attestation %x" % algorithm,
            0xFFFF,
            CAPABILITY.NONE,
            algorithm,
        )
        yield key
        key.delete()

    @pytest.mark.parametrize("algorithm", ASYM_ALGOS)
    def test_attestation(self, session, generated_key, algorithm, info):
        attkey, attcertobj, attcert = create_pair(session, algorithm)
        pubkey = attcert.public_key()

        # Verify signatures
        cert = generated_key.attest(attkey.id)
        data = cert.tbs_certificate_bytes
        if isinstance(pubkey, rsa.RSAPublicKey):
            pubkey.verify(
                cert.signature,
                data,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm,
            )
        else:
            pubkey.verify(cert.signature, data, ec.ECDSA(cert.signature_hash_algorithm))

        # Verify certificate extensions
        ext = AttestationExtensions.parse(cert)
        assert info.version == ext.firmware_version
        assert info.serial == ext.serial

        obj = generated_key.get_info()
        assert obj.origin == ext.origin
        assert obj.domains == ext.domains
        assert obj.capabilities == ext.capabilities
        assert obj.id == ext.object_id
        assert obj.label == ext.label

        # Verify correct public key
        assert cert.public_key() == generated_key.get_public_key()

        # Clean up
        attkey.delete()
        attcertobj.delete()


def test_fips_approved_attestation(session, connect_hsm):
    try:
        session.get_fips_status()
    except YubiHsmDeviceError:
        pytest.skip("Non-FIPS YubiHSM")

    try:
        # Configure into FIPS approved mode
        session.reset_device()
        sleep(5.0)
        hsm = connect_hsm()
        new_session = hsm.create_session_derived(1, "password")
        new_session.set_fips_mode(True)
        assert new_session.get_fips_status() == FIPS_STATUS.PENDING

        # Change the default auth key
        authkey = new_session.get_object(1, OBJECT.AUTHENTICATION_KEY)
        authkey.change_password("password2")
        assert new_session.get_fips_status() == FIPS_STATUS.ON

        # Generate keys
        key = AsymmetricKey.generate(
            new_session,
            0,
            "Test FIPS Attestation",
            0xFFFF,
            CAPABILITY.NONE,
            ALGORITHM.RSA_2048,
        )

        attkey, attcertobj, attcert = create_pair(new_session, ALGORITHM.RSA_2048)
        cert = key.attest(attkey.id)
        ext = AttestationExtensions.parse(cert)
        assert ext.fips_approved in (True, None)

    finally:
        # Reset device to get out of FIPS approved mode
        new_session.reset_device()
        sleep(5.0)
