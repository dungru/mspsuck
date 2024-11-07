# -*- coding: utf-8 -*-
import pytest

from apis.openwrt.device import Dut
from apis.utils import AttrDict


# from apis.openwrt.device import Dut
# from apis.openwrt.errors import OpenwrtError

pytest_plugins = [
    "apis.fixtures",
]


@pytest.fixture(scope="session")
def topo(request, adhoc):
    # if request.config.getoption("--skip_topo"):
    #     return
    topo = AttrDict()
    # sdk_env = []
    # skip_dut = request.config.getoption("--skip_dut")
    # grpc_user = request.config.getoption("--grpc_user")
    # clingenv_url = request.config.getoption("--clingenv_url")
    # skip_tg = request.config.getoption("--skip_tg_init")
    for host in adhoc.hosts:
        print(f"Connected by {str(host.name)}")
        topo[host.name] = Dut(adhoc, host, [])

    yield topo


def pytest_addoption(parser):
    parser.addoption(
        "--environment",
        action="store",
        default="dev",
        help="Specifyi test environment",
    )


@pytest.fixture(scope="function")
def assertion_teardown(request, topo):
    yield
