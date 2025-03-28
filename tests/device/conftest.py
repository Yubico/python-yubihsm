from yubihsm import YubiHsm
from yubihsm.exceptions import YubiHsmDeviceError
from time import sleep
from functools import partial
from . import DEFAULT_KEY
import pytest
from typing import List


@pytest.fixture(scope="session")
def connect_hsm(pytestconfig):
    backend_uri = pytestconfig.getoption("backend")
    return partial(YubiHsm.connect, backend_uri)


@pytest.fixture(scope="module")
def hsm(connect_hsm):
    with connect_hsm() as hsm:
        yield hsm


@pytest.fixture(scope="module")
def info(hsm):
    return hsm.get_device_info()


@pytest.fixture(scope="module")
def session(hsm):
    with hsm.create_session_derived(1, DEFAULT_KEY) as session:
        yield session


_logged_version: List[bool] = []


@pytest.fixture(scope="module", autouse=True)
def _hsm_info(info, session, request):
    if not _logged_version:  # Run only once
        name = "YubiHSM "
        try:
            session.get_fips_status()
            name += "FIPS "
        except YubiHsmDeviceError:
            pass
        name += "v" + (".".join(str(v) for v in info.version))

        capmanager = request.config.pluginmanager.getplugin("capturemanager")
        with capmanager.global_and_fixture_disabled():
            print()
            print()
            print("ℹ️  Running tests on", name)
            print()
        _logged_version.append(True)


@pytest.fixture(autouse=True, scope="session")
def _reset_hsm(connect_hsm):
    with connect_hsm() as hsm:
        with hsm.create_session_derived(1, DEFAULT_KEY) as session:
            session.reset_device()
    sleep(5.0)
