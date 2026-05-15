import base64
from types import SimpleNamespace

from geoip2.errors import GeoIP2Error

import check_vpn_risk
from check_vpn_risk import annotate_servers_with_maxmind, build_maxmind_record


def encode_openvpn_config(config):
    return base64.b64encode(config.encode("utf-8")).decode("ascii")


class FakeReader:
    def __init__(self, value=None, error=None):
        self.value = value
        self.error = error

    def city(self, ip):
        if self.error:
            raise self.error
        return self.value

    def country(self, ip):
        if self.error:
            raise self.error
        return self.value

    def asn(self, ip):
        if self.error:
            raise self.error
        return self.value


def named_record(**kwargs):
    defaults = {
        "iso_code": None,
        "name": None,
        "names": {},
        "is_in_european_union": False,
        "geoname_id": None,
        "code": None,
    }
    defaults.update(kwargs)
    return SimpleNamespace(**defaults)


def test_build_mihomo_openvpn_config_decodes_vpngate_servers():
    openvpn_config = """client
dev tun
proto udp
remote vpn.example.com 1194
cipher AES-128-CBC
auth SHA1
<ca>
-----BEGIN CERTIFICATE-----
ca-data
-----END CERTIFICATE-----
</ca>
<cert>
-----BEGIN CERTIFICATE-----
cert-data
-----END CERTIFICATE-----
</cert>
<key>
-----BEGIN PRIVATE KEY-----
key-data
-----END PRIVATE KEY-----
</key>
"""
    data = {
        "data": {
            "servers": [
                {
                    "hostname": "public-vpn-219",
                    "countryshort": "JP",
                    "maxmind": {
                        "asn": {
                            "number": 36599,
                            "organization": "SoftEther Telecommunication Research Institute LLC",
                        }
                    },
                    "openvpn_configdata_base64": encode_openvpn_config(openvpn_config),
                }
            ]
        }
    }

    config = check_vpn_risk.build_mihomo_openvpn_config(data)

    assert config == {
        "proxies": [
            {
                "name": "JP AS36599 public-vpn-219",
                "type": "openvpn",
                "server": "vpn.example.com",
                "port": 1194,
                "proto": "udp",
                "dev": "tun",
                "cipher": "AES-128-CBC",
                "auth": "SHA1",
                "udp": True,
                "ca": "-----BEGIN CERTIFICATE-----\nca-data\n-----END CERTIFICATE-----",
                "cert": "-----BEGIN CERTIFICATE-----\ncert-data\n-----END CERTIFICATE-----",
                "key": "-----BEGIN PRIVATE KEY-----\nkey-data\n-----END PRIVATE KEY-----",
                "tls-crypt": "",
            }
        ]
    }


def test_build_mihomo_openvpn_config_sets_empty_tls_crypt_when_absent():
    data = {
        "data": {
            "servers": [
                {
                    "hostname": "public-vpn-219",
                    "openvpn_configdata_base64": encode_openvpn_config(
                        "proto tcp\nremote 219.100.37.206 443\n"
                    ),
                }
            ]
        }
    }

    config = check_vpn_risk.build_mihomo_openvpn_config(data)

    assert config["proxies"][0]["tls-crypt"] == ""


def test_build_mihomo_proxy_name_excludes_asn_organization():
    name = check_vpn_risk.build_mihomo_proxy_name(
        {
            "hostname": "public-vpn-219",
            "countryshort": "JP",
            "maxmind": {
                "asn": {
                    "number": 36599,
                    "organization": "SoftEther Telecommunication Research Institute LLC",
                }
            },
        }
    )

    assert name == "JP AS36599 public-vpn-219"
    assert "SoftEther" not in name


def test_render_mihomo_yaml_writes_proxies_with_block_scalars():
    config = {
        "proxies": [
            {
                "name": "public-vpn-219",
                "type": "openvpn",
                "server": "vpn.example.com",
                "port": 1194,
                "proto": "udp",
                "udp": True,
                "ca": "-----BEGIN CERTIFICATE-----\nca-data\n-----END CERTIFICATE-----",
            }
        ]
    }

    yaml = check_vpn_risk.render_mihomo_yaml(config)

    assert yaml == """proxies:
  - name: "public-vpn-219"
    type: "openvpn"
    server: "vpn.example.com"
    port: 1194
    proto: "udp"
    udp: true
    ca: |-
      -----BEGIN CERTIFICATE-----
      ca-data
      -----END CERTIFICATE-----
"""


def test_render_mihomo_yaml_quotes_plain_strings():
    config = {
        "proxies": [
            {
                "name": "node: one # from vpngate",
                "type": "openvpn",
                "server": "vpn:example.com",
                "port": 1194,
            }
        ]
    }

    yaml = check_vpn_risk.render_mihomo_yaml(config)

    assert yaml == """proxies:
  - name: "node: one # from vpngate"
    type: "openvpn"
    server: "vpn:example.com"
    port: 1194
"""


def test_decode_openvpn_config_accepts_base64_with_outer_whitespace():
    encoded = encode_openvpn_config("proto tcp\nremote vpn.example.com 443\n")

    decoded = check_vpn_risk.decode_openvpn_config(f"\r\n{encoded}\r\n")

    assert decoded == "proto tcp\nremote vpn.example.com 443\n"


def test_build_mihomo_openvpn_config_skips_invalid_openvpn_data():
    data = {
        "data": {
            "servers": [
                {"hostname": "bad", "openvpn_configdata_base64": "not base64"},
                {
                    "hostname": "missing-remote",
                    "openvpn_configdata_base64": encode_openvpn_config("proto udp\n"),
                },
                {
                    "hostname": "bad-port",
                    "openvpn_configdata_base64": encode_openvpn_config(
                        "proto udp\nremote vpn.example.com not-a-port\n"
                    ),
                },
                {
                    "hostname": "bad-port-range",
                    "openvpn_configdata_base64": encode_openvpn_config(
                        "proto udp\nremote vpn.example.com 70000\n"
                    ),
                },
            ]
        }
    }

    config = check_vpn_risk.build_mihomo_openvpn_config(data)

    assert config == {"proxies": []}


def test_save_mihomo_openvpn_config_writes_yaml_file(tmp_path):
    data = {
        "data": {
            "servers": [
                {
                    "hostname": "public-vpn-219",
                    "openvpn_configdata_base64": encode_openvpn_config(
                        "proto tcp\nremote 219.100.37.206 443\n"
                    ),
                }
            ]
        }
    }
    output = tmp_path / "mihomo_openvpn.yaml"

    check_vpn_risk.save_mihomo_openvpn_config(data, str(output))

    assert output.read_text(encoding="utf-8") == """proxies:
  - name: "public-vpn-219"
    type: "openvpn"
    proto: "tcp"
    udp: false
    server: "219.100.37.206"
    port: 443
    tls-crypt: ""
"""


def test_build_mihomo_openvpn_config_uses_name_hostname_ip_fallback():
    openvpn_config = encode_openvpn_config("proto tcp\nremote vpn.example.com 443\n")
    data = {
        "data": {
            "servers": [
                {"name": "custom name", "hostname": "host", "ip": "192.0.2.1", "openvpn_configdata_base64": openvpn_config},
                {"hostname": "host", "ip": "192.0.2.2", "openvpn_configdata_base64": openvpn_config},
                {"ip": "192.0.2.3", "openvpn_configdata_base64": openvpn_config},
            ]
        }
    }

    config = check_vpn_risk.build_mihomo_openvpn_config(data)

    assert [proxy["name"] for proxy in config["proxies"]] == ["custom name", "host", "192.0.2.3"]


def test_build_maxmind_record_uses_supported_geoip_fields_only():
    city_response = SimpleNamespace(
        country=named_record(iso_code="JP", name="Japan", names={"en": "Japan"}),
        registered_country=named_record(iso_code="JP", name="Japan", names={"en": "Japan"}),
        continent=named_record(code="AS", name="Asia", names={"en": "Asia"}),
        city=named_record(name="Tokyo", names={"en": "Tokyo"}, geoname_id=1850147),
        subdivisions=SimpleNamespace(
            most_specific=named_record(
                iso_code="13",
                name="Tokyo",
                names={"en": "Tokyo"},
                geoname_id=1850144,
            )
        ),
        location=SimpleNamespace(
            latitude=35.6895,
            longitude=139.6917,
            accuracy_radius=20,
            time_zone="Asia/Tokyo",
        ),
        postal=SimpleNamespace(code="100-0001"),
    )
    asn_response = SimpleNamespace(
        autonomous_system_number=36599,
        autonomous_system_organization="SoftEther Telecommunication Research Institute LLC",
        network="219.100.37.0/24",
    )

    record = build_maxmind_record(
        "219.100.37.96",
        city_reader=FakeReader(city_response),
        country_reader=FakeReader(city_response),
        asn_reader=FakeReader(asn_response),
    )

    assert record == {
        "country": {
            "iso_code": "JP",
            "name": "Japan",
            "names": {"en": "Japan"},
            "is_in_european_union": False,
        },
        "registered_country": {
            "iso_code": "JP",
            "name": "Japan",
            "names": {"en": "Japan"},
            "is_in_european_union": False,
        },
        "continent": {"code": "AS", "name": "Asia", "names": {"en": "Asia"}},
        "city": {"name": "Tokyo", "names": {"en": "Tokyo"}, "geoname_id": 1850147},
        "subdivision": {
            "iso_code": "13",
            "name": "Tokyo",
            "names": {"en": "Tokyo"},
            "geoname_id": 1850144,
        },
        "location": {
            "latitude": 35.6895,
            "longitude": 139.6917,
            "accuracy_radius": 20,
            "time_zone": "Asia/Tokyo",
        },
        "postal": {"code": "100-0001"},
        "asn": {
            "number": 36599,
            "organization": "SoftEther Telecommunication Research Institute LLC",
            "network": "219.100.37.0/24",
        },
    }
    assert "threat" not in record
    assert "risk_score" not in record
    assert "is_vpn" not in record


def test_annotate_servers_replaces_old_ipdata_with_maxmind():
    servers = [{"ip": "219.100.37.96", "ipdata": {"threat": {"is_vpn": True}}}]
    city_response = SimpleNamespace(
        country=named_record(iso_code="JP", name="Japan"),
        registered_country=named_record(iso_code="JP", name="Japan"),
        continent=named_record(code="AS", name="Asia"),
        city=named_record(name="Tokyo"),
        subdivisions=SimpleNamespace(most_specific=named_record()),
        location=SimpleNamespace(latitude=None, longitude=None, accuracy_radius=None, time_zone=None),
        postal=SimpleNamespace(code=None),
    )
    asn_response = SimpleNamespace(
        autonomous_system_number=36599,
        autonomous_system_organization="SoftEther Telecommunication Research Institute LLC",
        network="219.100.37.0/24",
    )

    stats = annotate_servers_with_maxmind(
        servers,
        city_reader=FakeReader(city_response),
        country_reader=FakeReader(city_response),
        asn_reader=FakeReader(asn_response),
    )

    assert stats == {"annotated": 1, "failed": 0, "skipped": 0}
    assert "ipdata" not in servers[0]
    assert servers[0]["maxmind"]["country"]["iso_code"] == "JP"
    assert servers[0]["maxmind"]["asn"]["number"] == 36599


def test_annotate_servers_removes_old_ipdata_when_lookup_fails():
    servers = [{"ip": "not-an-ip", "ipdata": {"threat": {"is_vpn": True}}}]

    stats = annotate_servers_with_maxmind(
        servers,
        city_reader=FakeReader(error=ValueError("invalid IP")),
        country_reader=FakeReader(error=ValueError("invalid IP")),
        asn_reader=FakeReader(error=ValueError("invalid IP")),
    )

    assert stats == {"annotated": 0, "failed": 1, "skipped": 0}
    assert "ipdata" not in servers[0]
    assert "maxmind" not in servers[0]


def test_annotate_servers_continues_when_geoip_reader_raises_error():
    servers = [{"ip": "219.100.37.96", "ipdata": {"threat": {"is_vpn": True}}}]

    stats = annotate_servers_with_maxmind(
        servers,
        city_reader=FakeReader(error=GeoIP2Error("reader failed")),
        country_reader=FakeReader(error=GeoIP2Error("reader failed")),
        asn_reader=FakeReader(error=GeoIP2Error("reader failed")),
    )

    assert stats == {"annotated": 0, "failed": 1, "skipped": 0}
    assert "ipdata" not in servers[0]
    assert "maxmind" not in servers[0]


def test_annotate_servers_skips_missing_ip_and_clears_stale_data():
    servers = [{"hostname": "missing", "ipdata": {"threat": {"is_vpn": True}}}]

    stats = annotate_servers_with_maxmind(
        servers,
        city_reader=FakeReader(),
        country_reader=FakeReader(),
        asn_reader=FakeReader(),
    )

    assert stats == {"annotated": 0, "failed": 0, "skipped": 1}
    assert "ipdata" not in servers[0]
    assert "maxmind" not in servers[0]
