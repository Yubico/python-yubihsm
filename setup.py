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

import re
from setuptools import setup, find_packages


def get_version():
    with open("yubihsm/__init__.py", "r") as f:
        match = re.search(r"(?m)^__version__\s*=\s*['\"](.+)['\"]$", f.read())
        return match.group(1)


setup(
    name="yubihsm",
    version=get_version(),
    description="Python library for the YubiHSM 2",
    url="https://developers.yubico.com/YubiHSM2/",
    author="Yubico",
    author_email="yubico@yubico.com",
    classifiers=[
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Development Status :: 5 - Production/Stable",
        "License :: OSI Approved :: Apache Software License",
        "Topic :: Security :: Cryptography",
        "Topic :: Software Development :: Libraries",
    ],
    packages=find_packages(exclude=["test", "test.*"]),
    test_suite="test",
    install_requires=["six", "cryptography>=2.2,<43"],
    extras_require={"http": ["requests"], "usb": ["pyusb"]},
    tests_require=["mock", "cryptography>=2.6"],
)
