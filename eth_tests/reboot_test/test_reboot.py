# -*- coding: utf-8 -*-


def test_reboot_01(topo):
    """
    Steps:
    """
    # Stage1 Load port information from config YAML
    # make test TYPE=eth_tests ENV=dut117
    # pl = topo.dut1.get_ports(4, "pg")
    # topo.dut1.chip_config_set_port_list(pl)

    # Stage2 Packet construct

    # Stage3 Machine Setup DUT

    # Stage4 IXIA Setup

    # Stage5 Verification
    # Packet count check

    # Packet compare
    try:
        stdout, klog = topo.dut1.shell("iwpriv rax0 show pleinfo")
        print(f"{klog}")
        stdout, klog = topo.dut2.shell("uname -a")
        print(f"{stdout}")
        stdout = topo.dut3.shell_local_ns("iwpriv rax0 show vlaninfo")
        print(f"{stdout}")
        # stdout = topo.dut4.shell_ns("iwpriv rax0 stat")
        # print(f"{stdout}")
    except Exception as e:
        print(f"Error executing shell command: {e}")
        raise
    print("[P.A.S.S]")
