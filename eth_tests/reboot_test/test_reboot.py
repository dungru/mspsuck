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
        stdout = topo.dut1.shell("reboot")
    except Exception as e:
        print(f"Error executing shell command: {e}")
        raise
    print(stdout)
    print("[P.A.S.S]")
