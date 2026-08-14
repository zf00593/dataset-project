"""
settlements.py
==============

Location spreading for the incident generator.

PROBLEM THIS SOLVES

The original generator picked one of ~71 city anchors and jittered by ±0.15°.
At 1,000 rows that looked fine. At 30,000 rows every incident stacks into 71
dots, which is both ugly and wrong: charities, councils, GP practices, schools
and small manufacturers are overwhelmingly NOT headquartered in city centres.

APPROACH

Three settlement types, weighted by organisation type:

  city   — one of the named metro anchors, small jitter
  town   — a named secondary town where we have one, else a satellite offset
  rural  — a larger offset from the nearest named place, bearing biased inland

Rural bearings are biased toward the country centroid rather than drawn
uniformly. A uniform bearing off a coastal anchor like Brighton or Aberdeen
drops a meaningful share of points into the sea. The bias does not eliminate
that — there is no coastline test here without a shapefile — but it cuts it
sharply. If you need guaranteed-on-land points, that needs a real geometry
dependency, and you should not pretend precision this data does not have.

The resulting coordinates are FICTIONAL PLACEMENTS for synthetic rows. They
exist so a map reads as a country rather than a constellation. They are not
claims that anything happened at that point.
"""

from __future__ import annotations

import math
import random

from geo_reference import CITIES, COUNTRY_META

# Named secondary towns where having real names matters most (UK-heavy, since
# that is the audience). (name, lat, lon)
TOWNS = {
    "GB": [
        ("Scarborough", 54.283, -0.399), ("Truro", 50.263, -5.051),
        ("Kendal", 54.328, -2.745), ("Hereford", 52.056, -2.716),
        ("Lowestoft", 52.478, 1.751), ("Bangor", 53.228, -4.128),
        ("Dumfries", 55.070, -3.605), ("Elgin", 57.649, -3.316),
        ("Barnstaple", 51.081, -4.058), ("Louth", 53.367, -0.005),
        ("Whitehaven", 54.549, -3.588), ("Boston", 52.979, -0.026),
        ("Aberystwyth", 52.415, -4.083), ("Oban", 56.415, -5.471),
        ("Berwick-upon-Tweed", 55.771, -2.005), ("Bridgwater", 51.128, -2.994),
        ("Grantham", 52.912, -0.641), ("Kidderminster", 52.388, -2.250),
        ("Penrith", 54.665, -2.754), ("Melton Mowbray", 52.766, -0.886),
        ("Bury St Edmunds", 52.246, 0.711), ("Haverfordwest", 51.801, -4.969),
        ("Thurso", 58.594, -3.522), ("Stranraer", 54.903, -5.026),
    ],
    "US": [
        ("Bozeman", 45.680, -111.038), ("Ithaca", 42.443, -76.502),
        ("Duluth", 46.787, -92.100), ("Roanoke", 37.271, -79.941),
        ("Flagstaff", 35.198, -111.651), ("Bangor", 44.801, -68.778),
        ("Grand Junction", 39.064, -108.551), ("Dothan", 31.223, -85.390),
        ("Sioux Falls", 43.550, -96.700), ("Missoula", 46.872, -113.994),
        ("Wichita Falls", 33.914, -98.493), ("Traverse City", 44.763, -85.620),
    ],
    "IE": [("Sligo", 54.270, -8.476), ("Tralee", 52.270, -9.700),
           ("Athlone", 53.423, -7.941)],
    "AU": [("Toowoomba", -27.560, 151.954), ("Bendigo", -36.758, 144.278),
           ("Kalgoorlie", -30.749, 121.466), ("Launceston", -41.439, 147.137)],
    "CA": [("Kamloops", 50.675, -120.341), ("Sudbury", 46.492, -80.993),
           ("Moncton", 46.088, -64.778)],
    "NZ": [("Napier", -39.493, 176.912), ("Invercargill", -46.413, 168.351)],
    "DE": [("Görlitz", 51.155, 14.987), ("Flensburg", 54.792, 9.437),
           ("Passau", 48.573, 13.457)],
    "FR": [("Limoges", 45.833, 1.261), ("Quimper", 47.996, -4.098),
           ("Rodez", 44.350, 2.575)],
    "ES": [("Teruel", 40.344, -1.107), ("Lugo", 43.012, -7.556)],
    "IT": [("Potenza", 40.642, 15.799), ("Belluno", 46.140, 12.216)],
    "SE": [("Östersund", 63.179, 14.636), ("Kalmar", 56.663, 16.357)],
    "NO": [("Bodø", 67.280, 14.405), ("Ålesund", 62.472, 6.155)],
    "PL": [("Zamość", 50.716, 23.252), ("Suwałki", 54.102, 22.930)],
    "IN": [("Madurai", 9.925, 78.120), ("Guwahati", 26.145, 91.736),
           ("Udaipur", 24.585, 73.712)],
    "ZA": [("Polokwane", -23.904, 29.469), ("George", -33.963, 22.461)],
    "KE": [("Kisumu", -0.092, 34.768), ("Eldoret", 0.514, 35.270)],
    "NG": [("Jos", 9.897, 8.858), ("Enugu", 6.459, 7.548)],
    "BR": [("Cuiabá", -15.601, -56.098), ("Teresina", -5.092, -42.804)],
    "MX": [("Oaxaca", 17.073, -96.727), ("Durango", 24.028, -104.653)],
}

# City-states have no meaningful hinterland. Offsetting from Singapore by 0.4°
# puts the point in Johor or the Strait, i.e. another country entirely.
CITY_STATES = {"SG"}

# Approximate land bounding boxes, used only to clamp offsets back inside the
# country. Clamping is crude — a clamped point can still sit just offshore —
# but it prevents the worst failure, which is an incident attributed to the
# wrong country because an offset crossed a border.
# (lat_min, lat_max, lon_min, lon_max)
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


def _clamp(country, lat, lon):
    b = BBOX.get(country)
    if not b:
        return lat, lon
    return min(max(lat, b[0]), b[1]), min(max(lon, b[2]), b[3])


# How likely each org type is to sit outside a metro centre.
SETTLEMENT_WEIGHTS = {
    "nonprofit": {"city": 0.34, "town": 0.38, "rural": 0.28},
    "public":    {"city": 0.30, "town": 0.45, "rural": 0.25},
    "private":   {"city": 0.55, "town": 0.32, "rural": 0.13},
    "vendor":    {"city": 0.74, "town": 0.22, "rural": 0.04},
}


def _bearing_toward(lat, lon, target_lat, target_lon):
    """Compass bearing in radians from a point toward the country centroid."""
    return math.atan2(target_lon - lon, target_lat - lat)


def _offset(lat, lon, distance_deg, bearing_rad):
    """Move a point by a distance at a bearing, correcting longitude for latitude."""
    dlat = distance_deg * math.cos(bearing_rad)
    scale = max(math.cos(math.radians(lat)), 0.2)
    dlon = distance_deg * math.sin(bearing_rad) / scale
    return lat + dlat, lon + dlon


def place(country: str, org_type: str, rng: random.Random):
    """Pick a settlement type and coordinates for one synthetic organisation.

    Args:
        country (str): ISO2 code, must exist in CITIES.
        org_type (str): nonprofit / public / private / vendor.
        rng (random.Random): Seeded generator, so placements are reproducible.

    Returns:
        tuple: (settlement_type, place_label, lat, lon)
    """
    weights = SETTLEMENT_WEIGHTS.get(org_type, SETTLEMENT_WEIGHTS["private"])
    kind = rng.choices(list(weights), weights=list(weights.values()), k=1)[0]
    if country in CITY_STATES:
        kind = "city"

    cities = CITIES[country]
    towns = TOWNS.get(country, [])
    c_lat, c_lon = COUNTRY_META[country][3], COUNTRY_META[country][4]

    if kind == "city":
        name, lat, lon = rng.choice(cities)
        lat += rng.uniform(-0.09, 0.09)
        lon += rng.uniform(-0.09, 0.09)
        label = name

    elif kind == "town":
        if towns and rng.random() < 0.7:
            name, lat, lon = rng.choice(towns)
            lat += rng.uniform(-0.06, 0.06)
            lon += rng.uniform(-0.06, 0.06)
            label = name
        else:
            # Satellite of a metro: far enough out to separate on a map, close
            # enough to still be that town's travel-to-work area.
            name, lat, lon = rng.choice(cities)
            bearing = rng.uniform(0, 2 * math.pi)
            lat, lon = _offset(lat, lon, rng.uniform(0.18, 0.55), bearing)
            label = f"near {name}"

    else:  # rural
        anchor = rng.choice(towns + cities if towns else cities)
        name, lat, lon = anchor
        toward = _bearing_toward(lat, lon, c_lat, c_lon)
        # Bias inland: sample around the centroid bearing rather than uniformly,
        # which keeps most rural points off the sea without a coastline test.
        bearing = rng.gauss(toward, 0.9)
        lat, lon = _offset(lat, lon, rng.uniform(0.35, 1.5), bearing)
        label = f"rural, near {name}"

    lat, lon = _clamp(country, lat, lon)
    return kind, label, round(lat, 4), round(lon, 4)
