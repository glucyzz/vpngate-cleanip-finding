#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import logging
import os
import tempfile
from contextlib import ExitStack
from datetime import datetime
from typing import Any, Dict, Iterable, Optional

import geoip2.database
from geoip2.errors import AddressNotFoundError, GeoIP2Error
import requests
from dotenv import load_dotenv
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

load_dotenv()

VPNGATE_API_URL = os.getenv(
    "VPNGATE_API_URL",
    "https://raw.githubusercontent.com/6Kmfi6HP/Vpngate-Scraper-API/refs/heads/main/json/data.json",
)
MAXMIND_DB_DIR = os.getenv("MAXMIND_DB_DIR", "maxmind")
MAXMIND_COUNTRY_DB = os.getenv(
    "MAXMIND_COUNTRY_DB", os.path.join(MAXMIND_DB_DIR, "GeoLite2-Country.mmdb")
)
MAXMIND_CITY_DB = os.getenv(
    "MAXMIND_CITY_DB", os.path.join(MAXMIND_DB_DIR, "GeoLite2-City.mmdb")
)
MAXMIND_ASN_DB = os.getenv(
    "MAXMIND_ASN_DB", os.path.join(MAXMIND_DB_DIR, "GeoLite2-ASN.mmdb")
)
RETRY_TOTAL = int(os.getenv("RETRY_TOTAL", "5"))
RETRY_BACKOFF_FACTOR = float(os.getenv("RETRY_BACKOFF_FACTOR", "1"))
REQUEST_TIMEOUT = float(os.getenv("REQUEST_TIMEOUT", "10"))
OUTPUT_FILE = os.getenv("OUTPUT_FILE", "vpngate_with_risk.json")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


def create_session() -> requests.Session:
    session = requests.Session()
    retry = Retry(
        total=RETRY_TOTAL,
        backoff_factor=RETRY_BACKOFF_FACTOR,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["HEAD", "GET", "OPTIONS"],
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


def fetch_vpngate_data() -> Dict[str, Any]:
    logger.info("Fetching VPNGate data...")
    session = create_session()
    try:
        resp = session.get(VPNGATE_API_URL, timeout=REQUEST_TIMEOUT * 1.5)
        resp.raise_for_status()
        data = resp.json()
        if not isinstance(data, dict) or "data" not in data or "servers" not in data["data"]:
            raise ValueError("VPNGate 返回的数据格式不符合预期")
        return data
    finally:
        session.close()


def names_record(record: Any) -> Dict[str, Any]:
    return compact_dict(
        {
            "iso_code": getattr(record, "iso_code", None),
            "name": getattr(record, "name", None),
            "names": getattr(record, "names", None) or None,
            "is_in_european_union": getattr(record, "is_in_european_union", None),
        }
    )


def continent_record(record: Any) -> Dict[str, Any]:
    return compact_dict(
        {
            "code": getattr(record, "code", None),
            "name": getattr(record, "name", None),
            "names": getattr(record, "names", None) or None,
        }
    )


def city_record(record: Any) -> Dict[str, Any]:
    return compact_dict(
        {
            "name": getattr(record, "name", None),
            "names": getattr(record, "names", None) or None,
            "geoname_id": getattr(record, "geoname_id", None),
        }
    )


def subdivision_record(record: Any) -> Dict[str, Any]:
    return compact_dict(
        {
            "iso_code": getattr(record, "iso_code", None),
            "name": getattr(record, "name", None),
            "names": getattr(record, "names", None) or None,
            "geoname_id": getattr(record, "geoname_id", None),
        }
    )


def compact_dict(data: Dict[str, Any]) -> Dict[str, Any]:
    return {key: value for key, value in data.items() if value is not None}


def lookup(reader: Any, method: str, ip: str) -> Optional[Any]:
    try:
        return getattr(reader, method)(ip)
    except AddressNotFoundError:
        return None


def build_maxmind_record(ip: str, city_reader: Any, country_reader: Any, asn_reader: Any) -> Dict[str, Any]:
    country_response = lookup(country_reader, "country", ip)
    city_response = lookup(city_reader, "city", ip)
    asn_response = lookup(asn_reader, "asn", ip)

    response = city_response or country_response
    record: Dict[str, Any] = {}

    if response:
        country = names_record(getattr(response, "country", None))
        registered_country = names_record(getattr(response, "registered_country", None))
        continent = continent_record(getattr(response, "continent", None))
        city = city_record(getattr(response, "city", None))
        subdivision = subdivision_record(
            getattr(getattr(response, "subdivisions", None), "most_specific", None)
        )
        location_obj = getattr(response, "location", None)
        location = compact_dict(
            {
                "latitude": getattr(location_obj, "latitude", None),
                "longitude": getattr(location_obj, "longitude", None),
                "accuracy_radius": getattr(location_obj, "accuracy_radius", None),
                "time_zone": getattr(location_obj, "time_zone", None),
            }
        )
        postal = compact_dict({"code": getattr(getattr(response, "postal", None), "code", None)})

        if country:
            record["country"] = country
        if registered_country:
            record["registered_country"] = registered_country
        if continent:
            record["continent"] = continent
        if city:
            record["city"] = city
        if subdivision:
            record["subdivision"] = subdivision
        if location:
            record["location"] = location
        if postal:
            record["postal"] = postal

    if asn_response:
        asn = compact_dict(
            {
                "number": getattr(asn_response, "autonomous_system_number", None),
                "organization": getattr(asn_response, "autonomous_system_organization", None),
                "network": str(getattr(asn_response, "network", "")) or None,
            }
        )
        if asn:
            record["asn"] = asn

    return record


def annotate_servers_with_maxmind(
    servers: Iterable[Dict[str, Any]], city_reader: Any, country_reader: Any, asn_reader: Any
) -> Dict[str, int]:
    stats = {"annotated": 0, "failed": 0, "skipped": 0}
    for server in servers:
        server.pop("ipdata", None)
        server.pop("maxmind", None)
        ip = server.get("ip")
        if not ip:
            stats["skipped"] += 1
            continue
        try:
            record = build_maxmind_record(ip, city_reader, country_reader, asn_reader)
        except (GeoIP2Error, ValueError) as exc:
            logger.warning("IP %s 查询失败: %s", ip, exc)
            stats["failed"] += 1
            continue
        if record:
            server["maxmind"] = record
            stats["annotated"] += 1
        else:
            stats["failed"] += 1
    return stats



def save_atomic(data: Dict[str, Any], path: str) -> None:
    dirpath = os.path.dirname(path) or "."
    with tempfile.NamedTemporaryFile("w", delete=False, dir=dirpath, encoding="utf-8") as tmp:
        json.dump(data, tmp, indent=2, ensure_ascii=False)
        tmp_path = tmp.name
    os.replace(tmp_path, path)
    logger.info("Output saved to %s", path)


def main() -> None:
    start_dt = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    logger.info("Script started at %s", start_dt)

    try:
        vpn_data = fetch_vpngate_data()
        servers = vpn_data["data"]["servers"]
        logger.info("Found %d servers", len(servers))

        with ExitStack() as stack:
            country_reader = stack.enter_context(geoip2.database.Reader(MAXMIND_COUNTRY_DB))
            city_reader = stack.enter_context(geoip2.database.Reader(MAXMIND_CITY_DB))
            asn_reader = stack.enter_context(geoip2.database.Reader(MAXMIND_ASN_DB))
            stats = annotate_servers_with_maxmind(servers, city_reader, country_reader, asn_reader)

        logger.info(
            "MaxMind lookup complete: annotated=%d, failed=%d, skipped=%d",
            stats["annotated"],
            stats["failed"],
            stats["skipped"],
        )
        save_atomic(vpn_data, OUTPUT_FILE)
    except KeyboardInterrupt:
        logger.error("用户中断执行，已停止")
    except Exception as e:
        logger.exception("脚本运行出错: %s", e)
        raise


if __name__ == "__main__":
    main()
