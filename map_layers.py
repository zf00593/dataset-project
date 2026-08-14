"""
map_layers.py
=============

Five-layer interactive map of the incident dataset.

    python map_layers.py                    # -> figures/incident_map.html
    python map_layers.py --csv other.csv --out mymap.html
"""

from __future__ import annotations

import argparse
import os

import numpy as np
import pandas as pd
import plotly.graph_objects as go

from geo_reference import COUNTRY_META, ISO2_TO_ISO3
from incident_analysis import IncidentAnalysis

# The colour pallete
HUMAN = "#c1442f"
TECH = "#3d6b8e"
INK = "#1f2933"
MUTED = "#8896a6"
ARC = "rgba(193,68,47,0.30)"

POP = {k: v[5] for k, v in COUNTRY_META.items()}
CENTROID = {k: (v[3], v[4]) for k, v in COUNTRY_META.items()}
NAME = {k: v[0] for k, v in COUNTRY_META.items()}


def _country_layer(d: pd.DataFrame):
    """Records exposed per capita, per country of HQ."""
    # Groups by country and then sums the number of records affected per country
    g = d.groupby("country", observed=True)["records_affected"].sum()
    iso3, z, txt = [], [], []
    
    # Loops through the grouped data and calculates the records per capita for each country
    for iso2, total in g.items():
        if iso2 not in ISO2_TO_ISO3 or iso2 not in POP:
            continue
        iso3.append(ISO2_TO_ISO3[iso2])
        # Calculates the records per capita by dividing the total records affected by the population of the country (in millions) and rounding to 3 decimal places
        z.append(round(total / (POP[iso2] * 1e6), 3))
        # Creates a hover text for each country that includes the country name, total records affected, and records per capita
        txt.append(NAME[iso2])
    # returns the ISO3 country codes, records per capita, and hover text for each country
    return iso3, z, txt


def _imported_layer(d: pd.DataFrame):
    """Share of a country's exposure that traces to an organisation based elsewhere.
    """
    ex = d.copy()
    ex["subject_list"] = ex["data_subject_countries"].fillna("").str.split("|")
    ex = ex.explode("subject_list")
    ex = ex[ex["subject_list"].str.len() == 2]
    ex["foreign"] = ex["subject_list"] != ex["country"]

    g = ex.groupby("subject_list", observed=True)["foreign"]
    total, foreign = g.size(), g.sum()

    iso3, z, txt = [], [], []
    for iso2 in total.index:
        if iso2 not in ISO2_TO_ISO3 or total[iso2] < 3:
            continue                      # tiny denominators make noisy percentages
        pct = round(foreign[iso2] / total[iso2] * 100, 1)
        iso3.append(ISO2_TO_ISO3[iso2])
        z.append(pct)
        txt.append(f"{NAME.get(iso2, iso2)}<br>"
                   f"Incidents touching this country: {int(total[iso2])}<br>"
                   f"Of those, breached org was foreign: {int(foreign[iso2])}<br>"
                   f"<b>{pct}% of exposure is imported</b>")
    return iso3, z, txt


def _arc_layer(d: pd.DataFrame, cap: int = 300):
    """Supply-chain incidents only: HQ -> each affected country, as one trace.

    Segments are separated by None, which breaks the line between arcs.
    """
    sc = d[d["supply_chain"]].copy()
    sc["subject_list"] = sc["data_subject_countries"].fillna("").str.split("|")
    ex = sc.explode("subject_list")
    ex = ex[(ex["subject_list"].str.len() == 2) & (ex["subject_list"] != ex["country"])]
    ex = ex.sort_values("records_affected", ascending=False).head(cap)

    lons, lats = [], []
    for _, r in ex.iterrows():
        dest = CENTROID.get(r["subject_list"])
        if not dest or pd.isna(r["hq_lat"]):
            continue
        lons += [r["hq_lon"], dest[1], None]
        lats += [r["hq_lat"], dest[0], None]
    return lons, lats, len(ex)


def _bubble_layer(d: pd.DataFrame, vector_class: str):
    s = d[d["vector_class"] == vector_class]
    size = np.clip(np.sqrt(s["records_affected"].fillna(0)) / 260, 4.5, 40)
    tag = np.where(s["is_synthetic"], "SYNTHETIC", "REAL — see source column")
    custom = np.stack([
        s["sector"], s["attack_vector"],
        s["records_affected"].fillna(0), s["hq_city"], s["country_name"], tag,
    ], axis=-1)
    return s, size, custom


# --------------------------------------------------------------------------- #
# Build
# --------------------------------------------------------------------------- #

def build_map(a: IncidentAnalysis, out_path: str,
              start_year: int = 2019, end_year: int = 2026,
              max_points: int = 6000, embed_js: bool = True) -> str:
    df = a.df.dropna(subset=["hq_lat", "hq_lon", "date_discovered"]).copy()
    df["yr"] = df["date_discovered"].dt.year

    # Every point is repeated across 8 animation frames, so a 30k-row dataset
    # produces a ~24 MB HTML file that pans and zooms sluggishly — bad on a
    # projector. Sample the synthetic rows for DISPLAY only; all real incidents
    # are always kept. Analysis still runs on the full dataset.
    sampled_from = None
    if len(df) > max_points:
        sampled_from = len(df)
        real = df[~df["is_synthetic"]]
        syn = df[df["is_synthetic"]].sample(
            n=max(max_points - len(real), 1), random_state=42)
        df = pd.concat([real, syn]).sort_values("date_discovered")
    years = list(range(start_year, end_year + 1))

    def slice_to(y):
        return df[df["yr"] <= y]

    full = slice_to(years[-1])

    fig = go.Figure()

    # --- trace 0: choropleth, records per capita -------------------------- #
    iso3, z, txt = _country_layer(full)
    # One synthetic mega-incident in a small-population country (New Zealand hit
    # 98 records/person) otherwise flattens every other country to near-white.
    # Clamp the scale at the 90th percentile; hover still shows the true value.
    zcap = float(np.quantile(z, 0.90)) if z else 1.0
    fig.add_trace(go.Choropleth(
        locations=iso3, z=z, text=txt, colorscale="Blues", zmin=0, zmax=zcap,
        marker_line_color="white", marker_line_width=0.4, visible=False,
        colorbar=dict(title="Records per<br>capita (capped)", x=1.0, len=0.55,
                      thickness=12),
        hovertemplate="%{text}<br>%{z:.2f} records exposed per person<extra></extra>",
        name="Records per capita",
    ))

    # --- trace 1: choropleth, imported exposure (diverging) --------------- #
    iso3i, zi, txti = _imported_layer(full)
    fig.add_trace(go.Choropleth(
        locations=iso3i, z=zi, text=txti, colorscale="RdBu_r", zmid=50,
        zmin=0, zmax=100, marker_line_color="white", marker_line_width=0.4,
        visible=False,
        colorbar=dict(title="% of exposure<br>imported", x=1.0, len=0.55,
                      thickness=12, ticksuffix="%"),
        hovertemplate="%{text}<extra></extra>", name="Imported exposure",
    ))

    # --- trace 2: supply-chain arcs --------------------------------------- #
    alon, alat, n_arcs = _arc_layer(full)
    fig.add_trace(go.Scattergeo(
        lon=alon, lat=alat, mode="lines", line=dict(width=0.7, color=ARC),
        hoverinfo="skip", visible=False, name=f"Supply-chain data flows",
    ))

    # --- traces 3, 4: incident bubbles ------------------------------------ #
    for cls, colour in [("Human factor", HUMAN), ("Technical", TECH)]:
        s, size, custom = _bubble_layer(full, cls)
        fig.add_trace(go.Scattergeo(
            lon=s["hq_lon"], lat=s["hq_lat"], text=s["organisation"], mode="markers",
            name=cls, customdata=custom, visible=True,
            marker=dict(size=size, color=colour, opacity=0.72,
                        line=dict(width=np.where(s["is_synthetic"], 0.3, 1.6),
                                  color="white")),
            hovertemplate=("<b>%{text}</b><br>%{customdata[3]}, %{customdata[4]}<br>"
                           "%{customdata[0]}<br>Entry: %{customdata[1]}<br>"
                           "People affected: %{customdata[2]:,.0f}<br>"
                           "<i>%{customdata[5]}</i><extra></extra>"),
        ))

    # --- frames: data only, never `visible` -------------------------------- #
    frames = []
    for y in years:
        d = slice_to(y)
        i3, zz, tt = _country_layer(d)
        i3i, zzi, tti = _imported_layer(d)
        lo, la, _ = _arc_layer(d)
        hs, hsize, hcustom = _bubble_layer(d, "Human factor")
        ts, tsize, tcustom = _bubble_layer(d, "Technical")
        frames.append(go.Frame(name=str(y), traces=[0, 1, 2, 3, 4], data=[
            go.Choropleth(locations=i3, z=zz, text=tt),
            go.Choropleth(locations=i3i, z=zzi, text=tti),
            go.Scattergeo(lon=lo, lat=la),
            go.Scattergeo(lon=hs["hq_lon"], lat=hs["hq_lat"], text=hs["organisation"],
                          customdata=hcustom, marker=dict(size=hsize)),
            go.Scattergeo(lon=ts["hq_lon"], lat=ts["hq_lat"], text=ts["organisation"],
                          customdata=tcustom, marker=dict(size=tsize)),
        ]))
    fig.frames = frames

    # --- layer toggle buttons --------------------------------------------- #
    # Order: [per-capita, imported, arcs, bubbles-human, bubbles-technical]
    layers = {
        "1 · Incidents":        [False, False, False, True, True],
        "2 · + Supply chain":   [False, False, True, True, True],
        "3 · Per capita":       [True, False, False, True, True],
        "4 · Imported risk":    [False, True, False, False, False],
    }

    fig.update_layout(
        title=dict(
            text="<b>Where breaches happen — and whose data ends up in them</b>",
            x=0.01, y=0.97, font=dict(size=19, color=INK)),
        geo=dict(projection_type="natural earth", showland=True, landcolor="#f2f4f6",
                 showcountries=True, countrycolor="white", coastlinecolor="#dfe4ea",
                 showframe=False, bgcolor="white", lataxis_range=[-58, 82]),
        paper_bgcolor="white", margin=dict(l=0, r=0, t=104, b=118),
        # Explicit pixel height. Plotly's default container is height:100%, which
        # collapses to zero inside a body with no height in some browsers — the
        # page loads, the JS runs, and you see a blank white screen.
        height=780, autosize=True,
        legend=dict(orientation="h", y=1.02, x=0.42, font=dict(size=11)),
        updatemenus=[
            dict(type="buttons", direction="right", x=0.01, y=1.10, xanchor="left",
                 showactive=True, active=0, pad=dict(r=6),
                 font=dict(size=11),
                 buttons=[dict(label=k, method="restyle", args=[{"visible": v}])
                          for k, v in layers.items()]),
            dict(type="buttons", direction="left", x=0.01, y=-0.04, xanchor="left",
                 showactive=False, font=dict(size=11),
                 buttons=[
                     dict(label="▶ Play", method="animate", args=[None, dict(
                         frame=dict(duration=900, redraw=True), fromcurrent=True,
                         transition=dict(duration=300))]),
                     dict(label="❚❚ Pause", method="animate", args=[[None], dict(
                         frame=dict(duration=0, redraw=False), mode="immediate")]),
                 ]),
        ],
        sliders=[dict(
            active=len(years) - 1, x=0.13, len=0.84, y=-0.02, pad=dict(t=4),
            currentvalue=dict(prefix="Discovered up to end of ", font=dict(size=13)),
            steps=[dict(label=str(y), method="animate",
                        args=[[str(y)], dict(mode="immediate", frame=dict(
                            duration=350, redraw=True), transition=dict(duration=200))])
                   for y in years],
        )],
        annotations=[dict(
            x=0.01, y=-0.15, xref="paper", yref="paper", showarrow=False, align="left",
            font=dict(size=10.5, color=MUTED),
            text=(
                "Bubble size = people affected (square-root scaled). Thick white outline = "
                "one of 27 real public incidents; thin = synthetic.<br>"
                "<b>Arcs show where affected people live relative to the breached "
                "organisation — NOT attacker origin.</b> This dataset does not model "
                "attacker location.<br>"
                "Country patterns in the synthetic rows are artefacts of the generator's "
                "country weights, not measurements. Only the real rows carry a real place."
                + (f"<br><b>Displaying a random sample of {len(df):,} of {sampled_from:,} "
                   "incidents</b> — all real incidents kept, synthetic sampled for browser "
                   "performance. Percentages come from the full dataset."
                   if sampled_from else "")
            ))],
    )

    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    # embed_js=True inlines ~3.5 MB of plotly.js so the file works with no
    # internet and on networks that block cdn.plot.ly. Default on: a map that
    # fails to draw in the room is worse than a large file.
    fig.write_html(out_path, include_plotlyjs=True if embed_js else "cdn",
                   auto_play=False, full_html=True,
                   default_height="780px", default_width="100%")
    return out_path


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--csv", default="cyber_incidents.csv")
    p.add_argument("--out", default="figures/incident_map.html")
    p.add_argument("--start-year", type=int, default=2019)
    p.add_argument("--end-year", type=int, default=2026)
    p.add_argument("--max-points", type=int, default=6000,
                   help="display cap; real incidents are never dropped")
    p.add_argument("--cdn", action="store_true",
                   help="load plotly.js from CDN instead of embedding it "
                        "(smaller file, but needs internet to render)")
    args = p.parse_args()

    a = IncidentAnalysis(args.csv)
    path = build_map(a, args.out, args.start_year, args.end_year, args.max_points,
                     embed_js=not args.cdn)
    kb = os.path.getsize(path) // 1024
    mode = "plotly.js embedded — works offline" if not args.cdn else "CDN — needs internet"
    print(f"Wrote {path} ({kb} KB, {len(a.df)} incidents, "
          f"{args.start_year}-{args.end_year})\n  {mode}")


if __name__ == "__main__":
    main()
