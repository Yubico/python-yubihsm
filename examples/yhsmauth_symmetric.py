"""
This script will import a symmetric YubiHSM Auth credential to a YubiKey
and use that to establish an authenticated session with a YubiHSM device.

NOTE: The YubiHSM 2 device needs to be configured with an authentication key.
The default authentication key password on KeyID=1 is set to `password`, and this should
be changed or replaced with other authentication keys. This particular script, however,
assumes that the default authentication key is still present on the YubiHSM 2.

Furthermore, this script requires the `usb` extension of the `python-yubihsm` lib.
This can be installed using `pip install yubihsm[usb]` or `poetry install -E usb`.

Running this script requires a YubiKey with FW >= 5.4.3.

Usage: python yhsmauth_symmetric.py
"""

from yubihsm import YubiHsm
from yubikit.hsmauth import HsmAuthSession, DEFAULT_MANAGEMENT_KEY
from ykman import scripting as s

# Connect to a YubiKey
yubikey = s.single()

# Establish a YubiHSM Auth session
hsmauth = HsmAuthSession(yubikey.smart_card())

# Connect to a YubiHSM
hsm = YubiHsm.connect("yhusb://")

# Import a symmetric YubiHSM Auth credential (derived from a password) to YubiKey
# NOTE: the derivation password matches the default authentication
# key password on KeyID=1 in the YubiHSM.
credential = hsmauth.put_credential_derived(
    management_key=DEFAULT_MANAGEMENT_KEY,
    label="Default credential",
    credential_password="1234",
    derivation_password="password",
)

# Initiate mutual authentication process to YubiHSM
symmetric_auth = hsm.init_session(1)

# Calculate session keys
session_keys = hsmauth.calculate_session_keys_symmetric(
    label=credential.label, context=symmetric_auth.context, credential_password="1234"
)

# Authenticate the session
session = symmetric_auth.authenticate(*session_keys)
print("Session authenticated!")

# Random YubiHSM command over newly authenticated session
objects = session.list_objects()
print("YubiHSM Objects:")
print(objects)

# Clean up
session.close()
hsm.close()
