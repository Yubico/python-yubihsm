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

from yubihsm.defs import CAPABILITY, ALGORITHM
from yubihsm.objects import Opaque
from yubihsm.exceptions import YubiHsmInvalidRequestError
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
import os
import uuid
import datetime
import pytest


def test_put_empty(session):
    # Can't put an empty object
    with pytest.raises(ValueError):
        Opaque.put(
            session,
            0,
            "Test PUT empty Opaque",
            1,
            CAPABILITY.NONE,
            ALGORITHM.OPAQUE_DATA,
            b"",
        )


def test_data(session):
    for size in (1, 256, 1234, 1968):
        data = os.urandom(size)

        opaque = Opaque.put(
            session,
            0,
            "Test data Opaque",
            1,
            CAPABILITY.NONE,
            ALGORITHM.OPAQUE_DATA,
            data,
        )

        assert data == opaque.get()
        opaque.delete()


def test_put_too_big(session):
    with pytest.raises(YubiHsmInvalidRequestError):
        Opaque.put(
            session,
            0,
            "Test large Opaque",
            1,
            CAPABILITY.NONE,
            ALGORITHM.OPAQUE_DATA,
            os.urandom(1976),
        )

    # Make sure our session is still working
    assert len(session.get_pseudo_random(123)) == 123


def test_certificate(session):
    private_key = ec.generate_private_key(
        ALGORITHM.EC_P256.to_curve(), default_backend()
    )
    name = x509.Name(
        [x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, u"Test Certificate")]
    )
    one_day = datetime.timedelta(1, 0, 0)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .not_valid_before(datetime.datetime.today() - one_day)
        .not_valid_after(datetime.datetime.today() + one_day)
        .serial_number(int(uuid.uuid4()))
        .public_key(private_key.public_key())
        .sign(private_key, hashes.SHA256(), default_backend())
    )

    certobj = Opaque.put_certificate(
        session, 0, "Test certificate Opaque", 1, CAPABILITY.NONE, certificate
    )

    assert certificate == certobj.get_certificate()
    certobj.delete()
