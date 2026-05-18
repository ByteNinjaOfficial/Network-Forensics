from backend.services.nmap_scanner import _alerts_for_host, _parse_nmap_xml, _risk_score


def test_parse_nmap_xml_host_ports_and_vendor():
    xml = """<?xml version="1.0"?>
    <nmaprun>
      <host>
        <status state="up"/>
        <address addr="192.168.1.10" addrtype="ipv4"/>
        <address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="Example Vendor"/>
        <hostnames><hostname name="workstation"/></hostnames>
        <ports>
          <port protocol="tcp" portid="22"><state state="open"/></port>
          <port protocol="tcp" portid="80"><state state="closed"/></port>
          <port protocol="tcp" portid="443"><state state="open"/></port>
        </ports>
      </host>
    </nmaprun>
    """

    hosts = _parse_nmap_xml(xml)

    assert len(hosts) == 1
    assert hosts[0].ip_address == "192.168.1.10"
    assert hosts[0].hostname == "workstation"
    assert hosts[0].vendor == "Example Vendor"
    assert hosts[0].open_ports == [22, 443]


def test_risky_ports_raise_score_and_alerts():
    host = _parse_nmap_xml("""<nmaprun><host><status state="up"/><address addr="10.0.0.5" addrtype="ipv4"/><ports><port protocol="tcp" portid="23"><state state="open"/></port><port protocol="tcp" portid="445"><state state="open"/></port></ports></host></nmaprun>""")[0]

    assert _risk_score(host, is_new=True) >= 70
    alert_types = {alert.alert_type for alert in _alerts_for_host(host, "10.0.0.5", is_new=True)}
    assert {"NEW_DEVICE", "TELNET_OPEN", "SMB_EXPOSED"} <= alert_types
