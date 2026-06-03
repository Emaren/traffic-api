from __future__ import annotations

from pathlib import Path
from typing import Any

from app.services.traffic.config import DEV_GEO_OVERRIDES, GEOIP_DB_PATH

try:
    from geoip2.database import Reader as GeoIPReader
    from geoip2.errors import AddressNotFoundError
except Exception:  # pragma: no cover
    GeoIPReader = None  # type: ignore[assignment]
    AddressNotFoundError = Exception  # type: ignore[assignment]

_GEOIP_READER: Any | None = None
_GEOIP_READER_PATH: Path | None = None
_GEO_LOOKUP_CACHE: dict[str, dict[str, str]] = {}


def get_geo_reader() -> Any | None:
    global _GEOIP_READER, _GEOIP_READER_PATH

    if GeoIPReader is None:
        return None

    if _GEOIP_READER is not None and _GEOIP_READER_PATH == GEOIP_DB_PATH:
        return _GEOIP_READER

    if not GEOIP_DB_PATH.exists():
        return None

    try:
        if _GEOIP_READER is not None:
            try:
                _GEOIP_READER.close()
            except Exception:
                pass

        _GEOIP_READER = GeoIPReader(str(GEOIP_DB_PATH))
        _GEOIP_READER_PATH = GEOIP_DB_PATH
        return _GEOIP_READER
    except Exception:
        _GEOIP_READER = None
        _GEOIP_READER_PATH = None
        return None


def geoip_status() -> dict[str, Any]:
    db_exists = GEOIP_DB_PATH.exists()
    if GeoIPReader is None:
        return {
            "available": False,
            "db_exists": db_exists,
            "path": str(GEOIP_DB_PATH),
            "reason": "geoip2 package is not installed",
        }
    if not db_exists:
        return {
            "available": False,
            "db_exists": False,
            "path": str(GEOIP_DB_PATH),
            "reason": "GeoIP database is missing",
        }
    if get_geo_reader() is None:
        return {
            "available": False,
            "db_exists": True,
            "path": str(GEOIP_DB_PATH),
            "reason": "GeoIP database could not be opened",
        }
    return {
        "available": True,
        "db_exists": True,
        "path": str(GEOIP_DB_PATH),
        "reason": "GeoIP reader available",
    }


def get_geo_details(ip: str) -> dict[str, str]:
    if ip in _GEO_LOOKUP_CACHE:
        return _GEO_LOOKUP_CACHE[ip]

    if ip in DEV_GEO_OVERRIDES:
        override = {**DEV_GEO_OVERRIDES[ip], "geo_resolved": True}
        _GEO_LOOKUP_CACHE[ip] = override
        return override

    reader = get_geo_reader()
    if reader is not None:
        try:
            response = reader.city(ip)

            country = (
                response.country.name
                or response.registered_country.name
                or response.country.iso_code
                or response.registered_country.iso_code
                or "??"
            )

            area = ""
            if response.subdivisions and response.subdivisions.most_specific:
                area = (
                    response.subdivisions.most_specific.name
                    or response.subdivisions.most_specific.iso_code
                    or ""
                )

            city = response.city.name or ""

            result = {
                "country": country,
                "country_code": (
                    response.country.iso_code
                    or response.registered_country.iso_code
                    or ""
                ),
                "area": area,
                "city": city,
                "geo_resolved": True,
            }
            _GEO_LOOKUP_CACHE[ip] = result
            return result
        except AddressNotFoundError:
            pass
        except ValueError:
            pass
        except Exception:
            pass

    result = {"country": "Unknown", "country_code": "", "area": "", "city": "", "geo_resolved": False}
    _GEO_LOOKUP_CACHE[ip] = result
    return result
