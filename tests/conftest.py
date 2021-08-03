import pytest


def pytest_addoption(parser):
    parser.addoption("--domain", action="store")
    parser.addoption("--check-port", action="store")

@pytest.fixture
def domain(request):
    return request.config.getoption("--domain")

@pytest.fixture
def port(request):
    return request.config.getoption("--check-port")



