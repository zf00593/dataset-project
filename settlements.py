"""
settlements.py
==============

Location placement for the incident generator.

WHAT CHANGED AND WHY

v1 used ~71 hand-typed city anchors and jittered around them. Two problems
showed up at 30k rows: everything still clustered on those anchors, and rural
offsets dropped points into the sea because nothing checked whether the
coordinate was on land.

v2 uses real data:

  * geonamescache — 34,006 cities worldwide with population and coordinates.
    For the 26 countries here that is thousands of real anchors instead of 71,
    including 865 in the UK alone, down to ~15k population.

  * global-land-mask — a 1 km land/ocean grid. Every generated coordinate is
    tested and resampled until it lands on solid ground.

Both are optional. If either import fails the module falls back to the
hand-typed anchors in geo_reference, warns once on stderr, and skips the land
test — the generator still runs, the map just looks worse.

WHAT THE COORDINATES MEAN

For synthetic rows these are fictional placements, chosen so a map reads as a
populated country rather than a constellation of dots. A point near Kendal is
not a claim that anything happened near Kendal. Real incidents use their actual
HQ city and never pass through this module.
"""

from __future__ import annotations

import math
import random
import sys

from geo_reference import CITIES, COUNTRY_META  # noqa: F401  (COUNTRY_META kept for callers)

# --------------------------------------------------------------------------- #
# Optional data dependencies
# --------------------------------------------------------------------------- #

try:
    import geonamescache
    _GC = geonamescache.GeonamesCache()
    HAVE_CITIES = True
except Exception:                                    # pragma: no cover
    HAVE_CITIES = False

try:
    from global_land_mask import globe
    HAVE_LANDMASK = True
except Exception:                                    # pragma: no cover
    HAVE_LANDMASK = False

_WARNED = False


def _warn_once():
    global _WARNED
    if _WARNED:
        return
    missing = []
    if not HAVE_CITIES:
        missing.append("geonamescache missing (using ~71 built-in city anchors)")
    if not HAVE_LANDMASK:
        missing.append("global-land-mask missing (points may land in the sea)")
    if missing:
        print("settlements.py: " + "; ".join(missing) +
              "\n  pip install geonamescache global-land-mask", file=sys.stderr)
    _WARNED = True


# --------------------------------------------------------------------------- #
# City pools
# --------------------------------------------------------------------------- #

CITY_MIN_POP = 250_000
TOWN_MIN_POP = 15_000

_POOLS: dict[str, dict] = {}


def _pools(country: str):
    """Cities and towns for a country as (name, lat, lon, weight) lists.

    Sampling weight is population ** 0.4, NOT population. Raw population
    weighting sends a huge share of UK rows to London and undoes the point of
    having 865 anchors; the exponent keeps big cities likelier while leaving the
    long tail real probability mass.
    """
    if country in _POOLS:
        return _POOLS[country]

    cities, towns = [], []
    if HAVE_CITIES:
        for c in _GC.get_cities().values():
            if c["countrycode"] != country:
                continue
            pop = c.get("population") or 0
            if pop < TOWN_MIN_POP:
                continue
            entry = (c["name"], float(c["latitude"]), float(c["longitude"]), pop ** 0.4)
            (cities if pop >= CITY_MIN_POP else towns).append(entry)

    if not cities and not towns:
        _warn_once()
        cities = [(n, la, lo, 1.0) for n, la, lo in CITIES.get(country, [])]

    # Drop anchors whose own coordinate fails the land or bbox test. A handful
    # of small coastal cities have centroids that read as ocean on a 1 km grid;
    # excluding them here is cheaper than special-casing them at every call.
    cities = [c for c in cities if _valid(country, c[1], c[2])] or cities
    towns = [t for t in towns if _valid(country, t[1], t[2])] or towns

    if not cities:
        cities, towns = towns, []
    if not towns:
        towns = cities

    _POOLS[country] = {"city": cities, "town": towns}
    return _POOLS[country]


def _pick(pool, rng: random.Random):
    i = rng.choices(range(len(pool)), weights=[p[3] for p in pool], k=1)[0]
    return pool[i][0], pool[i][1], pool[i][2]


# --------------------------------------------------------------------------- #
# Geometry
# --------------------------------------------------------------------------- #

CITY_STATES = {"SG"}

# Approximate land bounding boxes. The land mask stops points falling in the
# sea; this stops them falling in the wrong COUNTRY, which the land mask cannot
# detect — a point in Johor is perfectly good land and completely wrong.
BBOX = {
    "GB": (50.0, 58.6, -7.5, 1.7),   "IE": (51.4, 55.3, -10.4, -6.0),
    "US": (25.5, 48.9, -124.5, -67.0), "CA": (43.0, 60.0, -135.0, -53.0),
    "AU": (-43.5, -11.0, 113.5, 153.5), "NZ": (-46.6, -34.4, 166.5, 178.5),
    "DE": (47.3, 54.9, 5.9, 15.0),   "FR": (42.4, 51.0, -4.7, 8.2),
    "NL": (50.8, 53.5, 3.4, 7.2),    "CH": (45.8, 47.8, 6.0, 10.4),
    "ES": (36.1, 43.7, -9.2, 3.3),   "IT": (36.7, 47.0, 6.7, 18.4),
    "SE": (55.4, 68.5, 11.2, 24.1),  "NO": (58.0, 70.9, 5.0, 30.9),
    "DK": (54.6, 57.7, 8.1, 12.6),   "PL": (49.0, 54.8, 14.2, 24.1),
    "IN": (8.2, 35.0, 68.3, 97.3),   "SG": (1.24, 1.46, 103.62, 104.03),
    "JP": (31.0, 45.4, 129.5, 145.8), "KR": (34.3, 38.5, 126.1, 129.6),
    "AE": (22.7, 26.0, 51.6, 56.3),  "ZA": (-34.8, -22.2, 16.5, 32.8),
    "KE": (-4.6, 4.6, 33.9, 41.8),   "NG": (4.3, 13.8, 2.7, 14.5),
    "BR": (-33.7, 4.2, -73.9, -34.8), "MX": (14.6, 32.6, -117.0, -86.8),
}

SETTLEMENT_WEIGHTS = {
    "nonprofit": {"city": 0.34, "town": 0.38, "rural": 0.28},
    "public":    {"city": 0.30, "town": 0.45, "rural": 0.25},
    "private":   {"city": 0.55, "town": 0.32, "rural": 0.13},
    "vendor":    {"city": 0.74, "town": 0.22, "rural": 0.04},
}


def _in_bbox(country, lat, lon):
    b = BBOX.get(country)
    return True if not b else (b[0] <= lat <= b[1] and b[2] <= lon <= b[3])


def _on_land(lat, lon):
    if not HAVE_LANDMASK:
        return True
    try:
        return bool(globe.is_land(lat, lon))
    except Exception:
        return True


def _valid(country, lat, lon):
    return _in_bbox(country, lat, lon) and _on_land(lat, lon)


def _offset(lat, lon, distance_deg, bearing_rad):
    dlat = distance_deg * math.cos(bearing_rad)
    scale = max(math.cos(math.radians(lat)), 0.2)
    dlon = distance_deg * math.sin(bearing_rad) / scale
    return lat + dlat, lon + dlon


def _scatter(country, lat, lon, lo, hi, rng, tries=25):
    """Offset from an anchor, resampling until the point is on land in-country.

    Falls back to the anchor itself if every attempt fails — which happens for
    anchors on small islands or narrow peninsulas, where there is genuinely
    nowhere within range to put it.
    """
    for _ in range(tries):
        blat, blon = _offset(lat, lon, rng.uniform(lo, hi), rng.uniform(0, 2 * math.pi))
        # Round FIRST, then validate. The land mask is a fine grid, and rounding
        # a validated coordinate to 4 dp can shift it across a cell boundary
        # from land to sea — which is exactly how ~1 in 2,000 coastal points
        # were still ending up offshore after every other check passed.
        blat, blon = round(blat, 4), round(blon, 4)
        if _valid(country, blat, blon):
            return blat, blon, True
    return round(lat, 4), round(lon, 4), False


def place(country: str, org_type: str, rng: random.Random):
    """Pick a settlement type and land-validated coordinates for one organisation.

    Args:
        country (str): ISO2 code.
        org_type (str): nonprofit / public / private / vendor.
        rng (random.Random): Seeded, so placements are reproducible.

    Returns:
        tuple: (settlement_type, place_label, lat, lon)
    """
    weights = SETTLEMENT_WEIGHTS.get(org_type, SETTLEMENT_WEIGHTS["private"])
    kind = rng.choices(list(weights), weights=list(weights.values()), k=1)[0]
    if country in CITY_STATES:
        kind = "city"

    pools = _pools(country)
    lo, hi = (0.01, 0.07) if kind in ("city", "town") else (0.12, 0.55)
    pool = pools["town" if kind == "rural" else kind]

    # Try several anchors, not just several offsets. A single anchor sitting on
    # a narrow coastal strip can fail every offset AND fail the land test at its
    # own coordinate, which is how the fallback used to emit a point at sea.
    for _ in range(6):
        name, lat, lon = _pick(pool, rng)
        plat, plon, ok = _scatter(country, lat, lon, lo, hi, rng)
        if ok:
            label = f"rural, near {name}" if kind == "rural" else name
            return kind, label, plat, plon
        if _valid(country, round(lat, 4), round(lon, 4)):
            return ("town" if kind == "rural" else kind), name, round(lat, 4), round(lon, 4)

    # Every anchor tried failed validation. Return the last one and let the
    # caller see a city-typed row rather than silently dropping the incident.
    return "city", name, round(lat, 4), round(lon, 4)
