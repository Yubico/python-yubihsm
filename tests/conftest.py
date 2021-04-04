def pytest_addoption(parser):
    parser.addoption("--backend", action="store", default="http://localhost:12345")
