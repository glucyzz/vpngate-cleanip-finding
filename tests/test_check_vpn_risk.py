from types import SimpleNamespace

from geoip2.errors import GeoIP2Error

from check_vpn_risk import annotate_servers_with_maxmind, build_maxmind_record


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
