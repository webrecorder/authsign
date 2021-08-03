import pytest


def pytest_addoption(parser):
    parser.addoption("--domain", action="store")


@pytest.fixture
def domain(request):
    return request.config.getoption("--domain")
