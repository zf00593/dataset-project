#!/usr/bin/env python3
"""
add_country.py
==============

Adds one or more countries to the incident dataset's geography config.

    python add_country.py PT SE-check --dry-run
    python add_country.py PT NO IT --weight 0.02

Everything except the sampling weight is derived from geonamescache:

  * name, region, ISO3 and population   -> COUNTRY_META in geo_reference.py
  * ISO2 -> ISO3 lookup                 -> ISO2_TO_ISO3 in geo_reference.py
  * bounding box from city coordinates  -> BBOX in settlements.py
  * city and town anchors               -> nothing to do, read at runtime

The sampling weight (how often synthetic incidents land in that country) is a
judgement call, so it defaults to a small value and you edit COUNTRIES in
generate_cyber_incidents.py yourself. This script prints the line to paste.

BOUNDING BOX CAVEAT

The box is the min/max of that country's known city coordinates, padded. That
works for compact mainland countries. It is WRONG for countries with distant
overseas territories or scattered islands — France would stretch to include
French Guiana, Norway to Svalbard — producing a box containing large amounts of
other countries' land and open sea. The script warns when a box looks
suspiciously large; check those by hand.
"""

from __future__ import annotations

import argparse
import re
import sys

import geonamescache

GC = geonamescache.GeonamesCache()

CONTINENT_TO_REGION = {
    "EU": "Europe", "NA": "Americas", "SA": "Americas", "AS": "Asia",
    "AF": "Africa", "OC": "Oceania", "AN": "Antarctica",
}

GEO_REF = "geo_reference.py"
SETTLEMENTS = "settlements.py"
GENERATOR = "generate_cyber_incidents.py"


def country_facts(iso2: str):
    countries = GC.get_countries()
    if iso2 not in countries:
        raise SystemExit(f"{iso2}: not a known ISO2 country code")
    c = countries[iso2]

    cities = [v for v in GC.get_cities().values() if v["countrycode"] == iso2]
    if not cities:
        raise SystemExit(f"{iso2} ({c['name']}): no cities in geonamescache, "
                         "placement would have nothing to anchor to")

    lats = [float(v["latitude"]) for v in cities]
    lons = [float(v["longitude"]) for v in cities]
    pad = 0.4
    bbox = (round(min(lats) - pad, 1), round(max(lats) + pad, 1),
            round(min(lons) - pad, 1), round(max(lons) + pad, 1))

    # Centroid of the largest city, not the bbox centre — the bbox centre of a
    # country with outlying territory can sit in the ocean.
    biggest = max(cities, key=lambda v: v.get("population") or 0)

    # Compare the box's area to the country's real land area. A span check
    # misses Portugal (the Azores sit 1,400 km west but only widen the box by
    # 20 degrees); an area ratio catches it, because the box is then mostly
    # Atlantic.
    import math
    lat_km = (bbox[1] - bbox[0]) * 111.0
    lon_km = (bbox[3] - bbox[2]) * 111.0 * math.cos(math.radians((bbox[0] + bbox[1]) / 2))
    box_area = abs(lat_km * lon_km)
    ratio = box_area / c["areakm2"] if c.get("areakm2") else 0

    return {
        "iso2": iso2,
        "area_ratio": round(ratio, 1),
        "iso3": c["iso3"],
        "name": c["name"],
        "region": CONTINENT_TO_REGION.get(c["continentcode"], "Unknown"),
        "lat": round(float(biggest["latitude"]), 2),
        "lon": round(float(biggest["longitude"]), 2),
        "pop_m": round((c["population"] or 0) / 1e6, 1),
        "bbox": bbox,
        "n_cities": len(cities),
        "span": (bbox[1] - bbox[0], bbox[3] - bbox[2]),
    }


def insert_into_dict(path: str, dict_name: str, new_line: str) -> bool:
    """Insert a line directly after `dict_name = {`.

    Anchoring on the dict declaration rather than on a specific existing entry:
    the entries are formatted inconsistently (ISO2_TO_ISO3 packs two pairs per
    line), so matching on one of them is fragile and can half-apply an edit.
    """
    src = open(path).read()
    m = re.search(rf"^{re.escape(dict_name)}\s*(?::[^=]+)?=\s*\{{[^\n]*\n", src, re.M)
    if not m:
        raise SystemExit(f"{path}: could not find `{dict_name} = {{`")
    at = m.end()

    # Scope the already-present check to THIS dict's body. Searching the whole
    # file finds the same country key in a different dict and silently skips a
    # write that was actually needed.
    end = src.find("\n}", at)
    body = src[at:end if end != -1 else len(src)]
    key = new_line.strip().split(":")[0]
    if re.search(rf"(?:^|\s){re.escape(key)}\s*:", body, re.M):
        return False
    open(path, "w").write(src[:at] + new_line + src[at:])
    return True


def main():
    p = argparse.ArgumentParser()
    p.add_argument("codes", nargs="*", help="ISO2 country codes, e.g. PT BE AT")
    p.add_argument("--all", action="store_true",
                   help="every country with enough city anchors to place into")
    p.add_argument("--min-cities", type=int, default=25,
                   help="with --all, skip countries below this many city anchors")
    p.add_argument("--max-area-ratio", type=float, default=3.0,
                   help="with --all, skip countries whose auto bounding box is this "
                        "many times their real land area (overseas territory)")
    p.add_argument("--write-weights", action="store_true",
                   help="rewrite the COUNTRIES dict in the generator with "
                        "population-derived weights")
    p.add_argument("--weight", type=float, default=0.01,
                   help="suggested sampling weight per country")
    p.add_argument("--dry-run", action="store_true", help="print, change nothing")
    args = p.parse_args()

    if args.all:
        codes, skipped = [], []
        for iso2 in sorted(GC.get_countries()):
            try:
                f = country_facts(iso2)
            except SystemExit:
                skipped.append((iso2, "no cities"))
                continue
            if f["n_cities"] < args.min_cities:
                skipped.append((iso2, f"only {f['n_cities']} cities"))
            elif f["area_ratio"] > args.max_area_ratio:
                skipped.append((iso2, f"bbox {f['area_ratio']}x land area"))
            else:
                codes.append(iso2)
        print(f"--all: {len(codes)} countries qualify, {len(skipped)} skipped "
              f"(min {args.min_cities} cities, max {args.max_area_ratio}x bbox)")
        print("  skipped: " + ", ".join(f"{c} ({why})" for c, why in skipped[:12])
              + (" ..." if len(skipped) > 12 else ""))
    else:
        codes = [c.upper() for c in args.codes]
    if not codes:
        raise SystemExit("nothing to do — pass country codes or --all")

    weight_lines, facts = [], []
    for code in codes:
        f = country_facts(code)

        if f["area_ratio"] > 3:
            print(f"  ! {code} ({f['name']}): bounding box is {f['area_ratio']}x the "
                  "country's actual land area — it probably includes overseas "
                  "territory or scattered islands, so most of the box is sea or "
                  "another country. Narrow it to the mainland by hand.",
                  file=sys.stderr)

        meta = (f'    "{f["iso2"]}": ("{f["name"]}", "{f["region"]}", "", '
                f'{f["lat"]}, {f["lon"]}, {f["pop_m"]}),\n')
        iso3 = f'    "{f["iso2"]}": "{f["iso3"]}",\n'
        bbox = (f'    "{f["iso2"]}": ({f["bbox"][0]}, {f["bbox"][1]}, '
                f'{f["bbox"][2]}, {f["bbox"][3]}),\n')

        print(f"\n{code} — {f['name']} ({f['region']}), {f['n_cities']} city anchors, "
              f"pop {f['pop_m']}M")
        if args.dry_run:
            print(f"  geo_reference.COUNTRY_META  {meta.strip()}")
            print(f"  geo_reference.ISO2_TO_ISO3  {iso3.strip()}")
            print(f"  settlements.BBOX            {bbox.strip()}")
        else:
            wrote_meta = insert_into_dict(GEO_REF, "COUNTRY_META", meta)
            wrote_iso3 = insert_into_dict(GEO_REF, "ISO2_TO_ISO3", iso3)
            wrote_bbox = insert_into_dict(SETTLEMENTS, "BBOX", bbox)
            done = [n for n, w in [("COUNTRY_META", wrote_meta),
                                   ("ISO2_TO_ISO3", wrote_iso3),
                                   ("BBOX", wrote_bbox)] if w]
            print("  added to: " + (", ".join(done) if done else "nothing (already present)"))

        facts.append(f)
        weight_lines.append(f'"{f["iso2"]}": {args.weight}')

    if args.write_weights and not args.dry_run:
        rewrite_weights(facts)
    else:
        print("\nWeights are a judgement call, so this script leaves COUNTRIES in "
              + GENERATOR + " alone unless you pass --write-weights.")
        print("Add: " + ", ".join(weight_lines))
    print("\nWeights need not sum to 1 — random.choices normalises them.")
    print("Regenerate:\n  python generate_cyber_incidents.py --rows 30000 --seed 42")


def rewrite_weights(facts):
    """Replace the COUNTRIES dict with population-derived weights.

    Weight is population ** 0.5, not population. Linear population weighting
    sends over half the dataset to India and the US and leaves most countries
    with a handful of rows each — useless on a map and useless for per-country
    statistics. The square root keeps big countries dominant while giving small
    ones a visible presence. It is a presentation choice, NOT an estimate of
    where incidents really occur, and nothing in this dataset should be read as
    a claim about relative national incident rates.
    """
    src = open(GENERATOR).read()
    total = sum(f["pop_m"] ** 0.5 for f in facts) or 1
    items = sorted(facts, key=lambda f: -f["pop_m"])
    lines, row = [], []
    for f in items:
        row.append(f'"{f["iso2"]}": {round(f["pop_m"] ** 0.5 / total, 4)}')
        if len(row) == 4:
            lines.append("    " + ", ".join(row) + ",")
            row = []
    if row:
        lines.append("    " + ", ".join(row) + ",")
    block = "COUNTRIES = {\n" + "\n".join(lines) + "\n}"

    # Find the dict's real extent by matching braces. A regex ending at the
    # first `}` at column 0 is wrong whenever the dict closes mid-line — which
    # it did here, so the replacement swallowed the NEXT dict in the file too.
    start = src.find("COUNTRIES = {")
    if start == -1:
        raise SystemExit(f"{GENERATOR}: could not locate the COUNTRIES dict")
    depth, i = 0, src.index("{", start)
    while i < len(src):
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1
            if depth == 0:
                break
        i += 1
    new = src[:start] + block + src[i + 1:]
    open(GENERATOR, "w").write(new)
    print(f"\nRewrote COUNTRIES in {GENERATOR} with {len(facts)} "
          "population-derived weights (sqrt-scaled).")


if __name__ == "__main__":
    main()
