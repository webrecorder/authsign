import pytest


def pytest_addoption(parser):
    parser.addoption("--domain", action="store")
    parser.addoption("--check-port", action="store")
    parser.addoption("--keep", action="store_true")


@pytest.fixture
def domain(request):
    return request.config.getoption("--domain")


@pytest.fixture
def port(request):
    return request.config.getoption("--check-port")


@pytest.fixture
def keep(request):
    return request.config.getoption("--keep")
