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

from typing import Optional

import usb.core
import usb.util

from ..exceptions import YubiHsmConnectionError
from . import YhsmBackend

YUBIHSM_VID = 0x1050
YUBIHSM_PID = 0x0030


class UsbBackend(YhsmBackend):
    """A backend for communicating with a YubiHSM directly over USB."""

    def __init__(self, serial: Optional[int] = None, timeout: Optional[int] = None):
        """Construct a UsbBackend, connected to a YubiHSM via USB.

        :param serial: (optional) The serial number of the YubiHSM to connect to.
        :param timeout: (optional) A read/write timeout in seconds.
        """
        err = None
        for device in usb.core.find(
            find_all=True, idVendor=YUBIHSM_VID, idProduct=YUBIHSM_PID
        ):  # type: ignore
            try:
                cfg = device.get_active_configuration()  # type: ignore
            except usb.core.USBError:
                cfg = None

            if cfg is None or cfg.bConfigurationValue != 0x01:  # type: ignore
                try:
                    device.set_configuration(0x01)  # type: ignore
                except usb.core.USBError as e:
                    err = YubiHsmConnectionError(e)
                    continue

            if serial is None or int(device.serial_number) == serial:  # type: ignore
                break

            usb.util.dispose_resources(device)
        else:
            raise err or YubiHsmConnectionError("No YubiHSM found.")

        # Flush any data waiting to be read
        try:
            device.read(0x81, 0xFFFF, 10)  # type: ignore
        except usb.core.USBError:
            pass  # Errors here are expected, and ignored

        self._device = device

        # pyusb expects milliseconds or None if no timeout
        self.timeout = None if timeout is None else timeout * 1000

    def transceive(self, msg):
        try:
            sent = self._device.write(0x01, msg, self.timeout)  # type: ignore
            if sent != len(msg):
                raise YubiHsmConnectionError("Error sending data over USB.")
            if sent % 64 == 0:
                if self._device.write(0x01, b"", self.timeout) != 0:  # type: ignore
                    raise YubiHsmConnectionError("Error sending data over USB.")
            return bytes(bytearray(self._device.read(0x81, 0xFFFF, self.timeout)))  # type: ignore
        except usb.core.USBError as e:
            raise YubiHsmConnectionError(e)

    def close(self):
        usb.util.dispose_resources(self._device)

    def __repr__(self):
        v_int = self._device.bcdDevice  # type: ignore
        version = "{}.{}.{}".format((v_int >> 8) & 0xF, (v_int >> 4) & 0xF, v_int & 0xF)
        return (
            "{0.__class__.__name__}(version={1}, serial={0._device.serial_number})"
        ).format(self, version)
