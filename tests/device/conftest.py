from yubihsm import YubiHsm
from time import sleep
from functools import partial
from . import DEFAULT_KEY
import pytest


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


@pytest.fixture(autouse=True, scope="session")
def _reset_hsm(connect_hsm):
    with connect_hsm() as hsm:
        with hsm.create_session_derived(1, DEFAULT_KEY) as session:
            session.reset_device()
    sleep(5.0)
