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

"""Named constants used in YubiHSM commands."""

from cryptography.hazmat.primitives.asymmetric import ec
from enum import IntEnum, IntFlag, unique


@unique
class ERROR(IntEnum):
    """Error codes returned by the YubiHSM"""

    OK = 0x00
    INVALID_COMMAND = 0x01
    INVALID_DATA = 0x02
    INVALID_SESSION = 0x03
    AUTHENTICATION_FAILED = 0x04
    SESSIONS_FULL = 0x05
    SESSION_FAILED = 0x06
    STORAGE_FAILED = 0x07
    WRONG_LENGTH = 0x08
    INSUFFICIENT_PERMISSIONS = 0x09
    LOG_FULL = 0x0A
    OBJECT_NOT_FOUND = 0x0B
    INVALID_ID = 0x0C
    SSH_CA_CONSTRAINT_VIOLATION = 0x0E
    INVALID_OTP = 0x0F
    DEMO_MODE = 0x10
    OBJECT_EXISTS = 0x11
    ALGORITHM_DISABLED = 0x12
    COMMAND_UNEXECUTED = 0xFF


@unique
class COMMAND(IntEnum):
    """Commands available to send to the YubiHSM"""

    ECHO = 0x01
    CREATE_SESSION = 0x03
    AUTHENTICATE_SESSION = 0x04
    SESSION_MESSAGE = 0x05
    DEVICE_INFO = 0x06
    RESET_DEVICE = 0x08
    GET_DEVICE_PUBLIC_KEY = 0x0A
    CLOSE_SESSION = 0x40
    GET_STORAGE_INFO = 0x041
    PUT_OPAQUE = 0x42
    GET_OPAQUE = 0x43
    PUT_AUTHENTICATION_KEY = 0x44
    PUT_ASYMMETRIC_KEY = 0x45
    GENERATE_ASYMMETRIC_KEY = 0x46
    SIGN_PKCS1 = 0x47
    LIST_OBJECTS = 0x48
    DECRYPT_PKCS1 = 0x49
    EXPORT_WRAPPED = 0x4A
    IMPORT_WRAPPED = 0x4B
    PUT_WRAP_KEY = 0x4C
    GET_LOG_ENTRIES = 0x4D
    GET_OBJECT_INFO = 0x4E
    SET_OPTION = 0x4F
    GET_OPTION = 0x50
    GET_PSEUDO_RANDOM = 0x51
    PUT_HMAC_KEY = 0x52
    SIGN_HMAC = 0x53
    GET_PUBLIC_KEY = 0x54
    SIGN_PSS = 0x55
    SIGN_ECDSA = 0x56
    DERIVE_ECDH = 0x57
    DELETE_OBJECT = 0x58
    DECRYPT_OAEP = 0x59
    GENERATE_HMAC_KEY = 0x5A
    GENERATE_WRAP_KEY = 0x5B
    VERIFY_HMAC = 0x5C
    SIGN_SSH_CERTIFICATE = 0x5D
    PUT_TEMPLATE = 0x5E
    GET_TEMPLATE = 0x5F
    DECRYPT_OTP = 0x60
    CREATE_OTP_AEAD = 0x61
    RANDOMIZE_OTP_AEAD = 0x62
    REWRAP_OTP_AEAD = 0x63
    SIGN_ATTESTATION_CERTIFICATE = 0x64
    PUT_OTP_AEAD_KEY = 0x65
    GENERATE_OTP_AEAD_KEY = 0x66
    SET_LOG_INDEX = 0x67
    WRAP_DATA = 0x68
    UNWRAP_DATA = 0x69
    SIGN_EDDSA = 0x6A
    BLINK_DEVICE = 0x6B
    CHANGE_AUTHENTICATION_KEY = 0x6C
    PUT_SYMMETRIC_KEY = 0x6D
    GENERATE_SYMMETRIC_KEY = 0x6E
    DECRYPT_ECB = 0x6F
    ENCRYPT_ECB = 0x70
    DECRYPT_CBC = 0x71
    ENCRYPT_CBC = 0x72

    ERROR = 0x7F


@unique
class ALGORITHM(IntEnum):
    """Various algorithm constants"""

    RSA_PKCS1_SHA1 = 1
    RSA_PKCS1_SHA256 = 2
    RSA_PKCS1_SHA384 = 3
    RSA_PKCS1_SHA512 = 4
    RSA_PSS_SHA1 = 5
    RSA_PSS_SHA256 = 6
    RSA_PSS_SHA384 = 7
    RSA_PSS_SHA512 = 8
    RSA_2048 = 9
    RSA_3072 = 10
    RSA_4096 = 11
    RSA_OAEP_SHA1 = 25
    RSA_OAEP_SHA256 = 26
    RSA_OAEP_SHA384 = 27
    RSA_OAEP_SHA512 = 28
    RSA_MGF1_SHA1 = 32
    RSA_MGF1_SHA256 = 33
    RSA_MGF1_SHA384 = 34
    RSA_MGF1_SHA512 = 35

    EC_P256 = 12
    EC_P384 = 13
    EC_P521 = 14
    EC_K256 = 15
    EC_BP256 = 16
    EC_BP384 = 17
    EC_BP512 = 18

    EC_ECDSA_SHA1 = 23
    EC_ECDH = 24

    HMAC_SHA1 = 19
    HMAC_SHA256 = 20
    HMAC_SHA384 = 21
    HMAC_SHA512 = 22

    AES128_CCM_WRAP = 29
    OPAQUE_DATA = 30
    OPAQUE_X509_CERTIFICATE = 31
    TEMPLATE_SSH = 36
    AES128_YUBICO_OTP = 37
    AES128_YUBICO_AUTHENTICATION = 38
    AES192_YUBICO_OTP = 39
    AES256_YUBICO_OTP = 40
    AES192_CCM_WRAP = 41
    AES256_CCM_WRAP = 42
    EC_ECDSA_SHA256 = 43
    EC_ECDSA_SHA384 = 44
    EC_ECDSA_SHA512 = 45
    EC_ED25519 = 46
    EC_P224 = 47
    RSA_PKCS1_DECRYPT = 48
    EC_P256_YUBICO_AUTHENTICATION = 49

    AES128 = 50
    AES192 = 51
    AES256 = 52
    AES_ECB = 53
    AES_CBC = 54

    def to_curve(self) -> ec.EllipticCurve:
        """Return a Cryptography EC curve instance for a given member.

        :return: The corresponding curve.
        :rtype: cryptography.hazmat.primitives.ec.

        :Example:

        >>> isinstance(ALGORITHM.EC_P256.to_curve(), ec.SECP256R1)
        True
        """

        return _curve_table[self]()  # type: ignore

    @staticmethod
    def for_curve(curve: ec.EllipticCurve) -> "ALGORITHM":
        """Returns a member corresponding to a Cryptography curve instance.

        :Example:

        >>> ALGORITHM.for_curve(ec.SECP256R1()) == ALGORITHM.EC_P256
        True
        """

        curve_type = type(curve)
        for key, val in _curve_table.items():
            if val == curve_type:
                return key
        raise ValueError("Unsupported curve type: %s" % curve.name)

    def to_key_size(self) -> int:
        """Return the expected size (in bytes) of a key corresponding to an algorithm.

        :return: The corresponding key size (in bytes) to an algorithm.

        :Example:

        >>> ALGORITHM.AES128.to_key_size()
        16
        """

        return _key_size_table[self]


_curve_table = {
    ALGORITHM.EC_P224: ec.SECP224R1,
    ALGORITHM.EC_P256: ec.SECP256R1,
    ALGORITHM.EC_P384: ec.SECP384R1,
    ALGORITHM.EC_P521: ec.SECP521R1,
    ALGORITHM.EC_K256: ec.SECP256K1,
    ALGORITHM.EC_BP256: ec.BrainpoolP256R1,
    ALGORITHM.EC_BP384: ec.BrainpoolP384R1,
    ALGORITHM.EC_BP512: ec.BrainpoolP512R1,
}

_key_size_table = {
    ALGORITHM.AES128_CCM_WRAP: 16,
    ALGORITHM.AES192_CCM_WRAP: 24,
    ALGORITHM.AES256_CCM_WRAP: 32,
    ALGORITHM.HMAC_SHA1: 64,  # Maximum key size
    ALGORITHM.HMAC_SHA256: 64,  # Maximum key size
    ALGORITHM.HMAC_SHA384: 128,  # Maximum key size
    ALGORITHM.HMAC_SHA512: 128,  # Maximum key size
    ALGORITHM.AES128_YUBICO_OTP: 16,
    ALGORITHM.AES192_YUBICO_OTP: 24,
    ALGORITHM.AES256_YUBICO_OTP: 32,
    ALGORITHM.AES128: 16,
    ALGORITHM.AES192: 24,
    ALGORITHM.AES256: 32,
}


@unique
class LIST_FILTER(IntEnum):
    """Keys for use to filter on in list_objects"""

    ID = 0x01
    TYPE = 0x02
    DOMAINS = 0x03
    CAPABILITIES = 0x04
    ALGORITHM = 0x05
    LABEL = 0x06


@unique
class OBJECT(IntEnum):
    """YubiHSM object types"""

    OPAQUE = 0x01
    AUTHENTICATION_KEY = 0x02
    ASYMMETRIC_KEY = 0x03
    WRAP_KEY = 0x04
    HMAC_KEY = 0x05
    TEMPLATE = 0x06
    OTP_AEAD_KEY = 0x07
    SYMMETRIC_KEY = 0x08


@unique
class OPTION(IntEnum):
    """YubiHSM device options"""

    FORCE_AUDIT = 0x01
    COMMAND_AUDIT = 0x03
    ALGORITHM_TOGGLE = 0x04
    FIPS_MODE = 0x05


@unique
class AUDIT(IntEnum):
    """Values for audit options"""

    OFF = 0x00
    ON = 0x01
    FIXED = 0x02


class _enum_prop:
    # Static property for use with enums.
    def __init__(self, getter):
        self.getter = getter

    def __get__(self, instance, cls):
        return self.getter(cls)


@unique
class CAPABILITY(IntFlag):
    """YubiHSM object capability flags"""

    GET_OPAQUE = 1 << 0x00
    PUT_OPAQUE = 1 << 0x01
    PUT_AUTHENTICATION_KEY = 1 << 0x02
    PUT_ASYMMETRIC = 1 << 0x03
    GENERATE_ASYMMETRIC_KEY = 1 << 0x04
    SIGN_PKCS = 1 << 0x05
    SIGN_PSS = 1 << 0x06
    SIGN_ECDSA = 1 << 0x07
    SIGN_EDDSA = 1 << 0x08
    DECRYPT_PKCS = 1 << 0x09
    DECRYPT_OAEP = 1 << 0x0A
    DERIVE_ECDH = 1 << 0x0B
    EXPORT_WRAPPED = 1 << 0x0C
    IMPORT_WRAPPED = 1 << 0x0D
    PUT_WRAP_KEY = 1 << 0x0E
    GENERATE_WRAP_KEY = 1 << 0x0F
    EXPORTABLE_UNDER_WRAP = 1 << 0x10
    SET_OPTION = 1 << 0x11
    GET_OPTION = 1 << 0x12
    GET_PSEUDO_RANDOM = 1 << 0x13
    PUT_HMAC_KEY = 1 << 0x14
    GENERATE_HMAC_KEY = 1 << 0x15
    SIGN_HMAC = 1 << 0x16
    VERIFY_HMAC = 1 << 0x17
    GET_LOG_ENTRIES = 1 << 0x18
    SIGN_SSH_CERTIFICATE = 1 << 0x19
    GET_TEMPLATE = 1 << 0x1A
    PUT_TEMPLATE = 1 << 0x1B
    RESET_DEVICE = 1 << 0x1C
    DECRYPT_OTP = 1 << 0x1D
    CREATE_OTP_AEAD = 1 << 0x1E
    RANDOMIZE_OTP_AEAD = 1 << 0x1F
    REWRAP_FROM_OTP_AEAD_KEY = 1 << 0x20
    REWRAP_TO_OTP_AEAD_KEY = 1 << 0x21
    SIGN_ATTESTATION_CERTIFICATE = 1 << 0x22
    PUT_OTP_AEAD_KEY = 1 << 0x23
    GENERATE_OTP_AEAD_KEY = 1 << 0x24
    WRAP_DATA = 1 << 0x25
    UNWRAP_DATA = 1 << 0x26
    DELETE_OPAQUE = 1 << 0x27
    DELETE_AUTHENTICATION_KEY = 1 << 0x28
    DELETE_ASYMMETRIC_KEY = 1 << 0x29
    DELETE_WRAP_KEY = 1 << 0x2A
    DELETE_HMAC_KEY = 1 << 0x2B
    DELETE_TEMPLATE = 1 << 0x2C
    DELETE_OTP_AEAD_KEY = 1 << 0x2D
    CHANGE_AUTHENTICATION_KEY = 1 << 0x2E
    PUT_SYMMETRIC_KEY = 1 << 0x2F
    GENERATE_SYMMETRIC_KEY = 1 << 0x30
    DELETE_SYMMETRIC_KEY = 1 << 0x31
    DECRYPT_ECB = 1 << 0x32
    ENCRYPT_ECB = 1 << 0x33
    DECRYPT_CBC = 1 << 0x34
    ENCRYPT_CBC = 1 << 0x35

    @_enum_prop
    def NONE(cls) -> "CAPABILITY":
        return cls(0)  # type: ignore

    @_enum_prop
    def ALL(cls) -> "CAPABILITY":
        return cls(sum(cls))  # type: ignore


class ORIGIN(IntFlag):
    GENERATED = 0x01
    IMPORTED = 0x02
    IMPORTED_WRAPPED = 0x10  # Set in combination with GENERATED/IMPORTED
