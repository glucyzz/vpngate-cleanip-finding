# VPNGate MaxMind Enricher

This project fetches VPNGate server data and enriches each server IP with local MaxMind GeoLite2 Country, City, and ASN data.

## Features

- Fetches the latest VPNGate server list
- Uses local MaxMind `.mmdb` databases instead of an external IP risk API
- Adds country, city, location, registered country, continent, subdivision, postal, and ASN information
- Saves the enriched result to `vpngate_with_risk.json`
- Generates a mihomo OpenVPN proxy file at `mihomo_openvpn.yaml`
- Includes a GitHub Actions workflow for automatic data updates

## Setup

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

Download the MaxMind databases into `maxmind/`:

```bash
mkdir -p maxmind
curl -fsSL "https://6kmfi6hp.github.io/maxmind/GeoLite2-Country.mmdb" -o maxmind/GeoLite2-Country.mmdb
curl -fsSL "https://6kmfi6hp.github.io/maxmind/GeoLite2-City.mmdb" -o maxmind/GeoLite2-City.mmdb
curl -fsSL "https://6kmfi6hp.github.io/maxmind/GeoLite2-ASN.mmdb" -o maxmind/GeoLite2-ASN.mmdb
```

No `IPDATA_API_KEY` or socks proxy is required.

## Usage

```bash
python check_vpn_risk.py
```

The program will:

1. Fetch the latest VPNGate server list
2. Look up each server IP in the local MaxMind databases
3. Save the result to `vpngate_with_risk.json`
4. Decode `openvpn_configdata_base64` and save mihomo OpenVPN proxies to `mihomo_openvpn.yaml`

## Output Format

Each server entry receives a `maxmind` field when lookup data is available. Supported fields include:

- `country`
- `registered_country`
- `continent`
- `city`
- `subdivision`
- `location`
- `postal`
- `asn`

MaxMind GeoLite2 does not provide VPN/proxy/threat scoring, so fields such as `is_vpn`, `is_proxy`, `is_tor`, `is_datacenter`, `risk_score`, and `threat` are not generated.

`mihomo_openvpn.yaml` contains a `proxies` list with `type: openvpn`. Each proxy name is built from the country ISO code, ASN number, and VPNGate server `name`, `hostname`, or `ip` field; ASN organization is not included. The generator maps OpenVPN `remote`, `proto`, `dev`, `cipher`, `auth`, `<ca>`, `<cert>`, `<key>`, and `<tls-crypt>` into mihomo fields.

## Automated Updates

`.github/workflows/update-vpngate-maxmind.yml` runs daily and can also be started manually. It downloads the three MaxMind databases, runs tests, regenerates `vpngate_with_risk.json`, and commits the data file only when it changes.
