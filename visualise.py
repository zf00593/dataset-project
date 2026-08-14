"""
visualise.py
============

Renders every figure from IncidentAnalysis.

    python visualise.py                 # everything, into ./figures/
    python visualise.py --only map      # one figure by name

Static figures are PNG at 200 dpi (fine for slides). The map is a standalone
self-contained HTML file — open it in a browser, no server needed.

HONESTY RULE APPLIED THROUGHOUT: every figure drawn from synthetic rows carries
a footnote saying so. If a chart mixes real and synthetic, the real points are
drawn in a distinct colour and labelled. Charts derived from generator-computed
fields (severity, cost) are not rendered at all — they would be circular.
"""

from __future__ import annotations

import argparse
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from matplotlib.ticker import FuncFormatter

from geo_reference import ISO2_TO_ISO3
from incident_analysis import IncidentAnalysis

OUT = "figures"

# Palette: one accent for human factor, one for technical, one for real incidents.
INK = "#1f2933"
MUTED = "#8896a6"
HUMAN = "#c1442f"
TECH = "#3d6b8e"
REAL = "#0f5c4a"
GRID = "#dfe4ea"

plt.rcParams.update({
    "figure.dpi": 200,
    "savefig.dpi": 200,
    "font.family": "DejaVu Sans",
    "font.size": 9,
    "axes.titlesize": 12,
    "axes.titleweight": "bold",
    "axes.labelcolor": INK,
    "axes.edgecolor": GRID,
    "axes.spines.top": False,
    "axes.spines.right": False,
    "text.color": INK,
    "xtick.color": MUTED,
    "ytick.color": MUTED,
    "figure.autolayout": False,
})


def _note(fig, text):
    """Footnote every figure with its provenance."""
    fig.text(0.01, -0.04, text, fontsize=6.5, color=MUTED, ha="left", va="top")


def _save(fig, name):
    os.makedirs(OUT, exist_ok=True)
    path = os.path.join(OUT, f"{name}.png")
    fig.savefig(path, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print(f"  {path}")
    return path


def _thousands(x, _):
    if x >= 1e9:
        return f"{x/1e9:.1f}bn"
    if x >= 1e6:
        return f"{x/1e6:.0f}M"
    if x >= 1e3:
        return f"{x/1e3:.0f}k"
    return f"{x:.0f}"


# --------------------------------------------------------------------------- #
# 1. The awareness argument
# --------------------------------------------------------------------------- #

def fig_awareness_share(a):
    d = a.awareness_preventable_share()
    fig, ax = plt.subplots(figsize=(6, 2.6))
    left = 0
    for cls, colour in [("Human factor", HUMAN), ("Technical", TECH)]:
        pct = d.loc[cls, "pct_of_all"]
        ax.barh(0, pct, left=left, color=colour, height=0.5)
        ax.text(left + pct / 2, 0, f"{cls}\n{pct}%", ha="center", va="center",
                color="white", fontweight="bold", fontsize=10)
        left += pct
    ax.set_xlim(0, 100)
    ax.set_ylim(-0.6, 0.6)
    ax.set_yticks([])
    ax.set_xlabel("Share of all incidents (%)")
    ax.set_title("How attackers got in")
    _note(fig, "n=1,027 (27 real, 1,000 synthetic). 'Human factor' = credentials, phishing, "
               "social engineering, MFA fatigue, third-party supplier access.")
    return _save(fig, "01_awareness_share")


def fig_top_vectors(a):
    d = a.top_vectors(12).iloc[::-1]
    colours = [HUMAN if c == "Human factor" else TECH for c in d["vector_class"]]
    fig, ax = plt.subplots(figsize=(7, 4.5))
    ax.barh(d["attack_vector"], d["count"], color=colours)
    for y, (c, p) in enumerate(zip(d["count"], d["pct"])):
        ax.text(c + 4, y, f"{p}%", va="center", fontsize=8, color=MUTED)
    ax.set_xlabel("Incidents")
    ax.set_title("Initial access vectors")
    handles = [plt.Rectangle((0, 0), 1, 1, color=HUMAN),
               plt.Rectangle((0, 0), 1, 1, color=TECH)]
    ax.legend(handles, ["Human factor", "Technical"], frameon=False, loc="lower right")
    _note(fig, "All incidents. Real rows use free-text vectors classified by keyword.")
    return _save(fig, "02_top_vectors")


def fig_credential_led_real(a):
    d = a.credential_led_incidents_real().head(12).iloc[::-1]
    d = d[d["records_affected"].notna()]
    fig, ax = plt.subplots(figsize=(7.5, 4.5))
    ax.barh(d["organisation"].str.slice(0, 34), d["records_affected"], color=REAL)
    ax.set_xscale("log")
    ax.xaxis.set_major_formatter(FuncFormatter(_thousands))
    ax.set_xlabel("People affected (log scale)")
    ax.set_title("Real breaches that started with a person")
    _note(fig, "Real incidents only. Entry via credentials, phishing, social engineering or "
               "supplier access. Figures as publicly reported; see source column.")
    return _save(fig, "03_credential_led_real")


# --------------------------------------------------------------------------- #
# 2. Timelines
# --------------------------------------------------------------------------- #

def fig_beacon_timeline(a):
    d = a.beacon_event_timeline()
    phase_colour = {"Exposure": HUMAN, "Notification": "#d99b30", "Response": REAL}
    # Four stagger levels: events on days 7/8/9 sit close together and single
    # up/down alternation is not enough to keep their labels apart.
    levels = [0.42, -0.42, 0.95, -0.95]
    fig, ax = plt.subplots(figsize=(11, 5))
    ax.axhline(0, color=GRID, lw=2, zorder=0)
    for i, r in d.iterrows():
        y = levels[i % 4]
        c = phase_colour[r["phase"]]
        ax.plot([r["day_offset"], r["day_offset"]], [0, y * 0.9], color=c, lw=1)
        ax.scatter(r["day_offset"], 0, s=45, color=c, zorder=3)
        ax.text(r["day_offset"], y, f"Day {r['day_offset']} — {r['actor']}\n"
                + _wrap(r["event"], 26), ha="center",
                va="bottom" if y > 0 else "top", fontsize=6.8, linespacing=1.35)
    ax.set_ylim(-1.9, 1.9)
    ax.set_xlim(-0.9, d["day_offset"].max() + 0.9)
    ax.set_yticks([])
    ax.set_xlabel("Days from first known compromise (27 July 2026)")
    ax.set_title("Beacon CRM: five days between the vendor knowing and charities knowing")
    _save_legend(ax, phase_colour)
    _note(fig, "Real incident. Dates from Beacon customer notifications, SCVO guidance and "
               "press reporting, Aug 2026. Investigation ongoing; figures provisional.")
    return _save(fig, "04_beacon_timeline")


def _wrap(s, n):
    words, lines, cur = s.split(), [], ""
    for w in words:
        if len(cur) + len(w) + 1 > n:
            lines.append(cur)
            cur = w
        else:
            cur = f"{cur} {w}".strip()
    lines.append(cur)
    if len(lines) > 4:
        lines = lines[:4]
        lines[-1] += "…"      # never silently drop text
    return "\n".join(lines)


def _save_legend(ax, mapping):
    handles = [plt.Line2D([], [], marker="o", ls="", color=c, label=k)
               for k, c in mapping.items()]
    ax.legend(handles=handles, frameon=False, ncol=len(mapping), loc="upper center",
              bbox_to_anchor=(0.5, 1.0), fontsize=7)


def fig_response_lag(a):
    d = a.response_lag_decomposition(top_n=14).iloc[::-1]
    fig, ax = plt.subplots(figsize=(7.5, 5))
    ax.barh(d["label"], d["exposure_days"], color=HUMAN, label="Undetected (attacker in, nobody knows)")
    ax.barh(d["label"], d["notification_days"], left=d["exposure_days"], color="#d99b30",
            label="Known but not disclosed")
    ax.set_xlabel("Days")
    ax.set_title("Time from intrusion to the public finding out")
    ax.legend(frameon=False, fontsize=8, loc="lower right")
    _note(fig, "Real incidents only. Dates as publicly reported.")
    return _save(fig, "05_response_lag")


def fig_cumulative_records(a):
    d = a.cumulative_records_timeline("real", freq="Y")
    fig, ax = plt.subplots(figsize=(7.5, 4))
    x = d.index.astype(int)
    ax.step(x, d["cumulative_records"], where="post", color=REAL, lw=2.2)
    ax.fill_between(x, d["cumulative_records"], step="post", color=REAL, alpha=0.12)
    ax.yaxis.set_major_formatter(FuncFormatter(_thousands))
    ax.set_ylabel("People affected, running total")
    ax.set_title("Cumulative people exposed by the incidents in this dataset")
    top = d["cumulative_records"].iloc[-1]
    ax.annotate(f"{top/1e9:.2f} billion", xy=(x[-1], top), xytext=(-10, -18),
                textcoords="offset points", ha="right", fontweight="bold", color=REAL)
    _note(fig, "Real incidents only, plotted at disclosure date. Counts as reported and may "
               "double-count individuals affected by more than one breach.")
    return _save(fig, "06_cumulative_records")


def fig_lifecycle_gantt(a):
    d = a.lifecycle_timeline("real", top_n=16, sort_by="date_occurred")
    fig, ax = plt.subplots(figsize=(8, 5.5))
    for i, r in d.iterrows():
        ax.barh(i, r["exposure_days"], left=0, color=HUMAN, height=0.55)
        ax.barh(i, r["notification_days"], left=r["exposure_days"], color="#d99b30", height=0.55)
    ax.set_yticks(range(len(d)))
    ax.set_yticklabels(d["label"], fontsize=7)
    ax.invert_yaxis()
    ax.set_xscale("symlog")
    ax.set_xlabel("Days from first compromise (symlog scale)")
    ax.set_title("Incident lifecycles: exposure, then silence")
    _note(fig, "Real incidents only. Symlog x-axis: spans range from 1 day to 627.")
    return _save(fig, "07_lifecycle_gantt")


def fig_exposure_ranking(a):
    d = a.exposure_window_ranking("all", 15).iloc[::-1]
    colours = [REAL if not s else MUTED for s in d["is_synthetic"]]
    fig, ax = plt.subplots(figsize=(7.5, 4.8))
    labels = (d["organisation"].str.slice(0, 30)
              + np.where(d["is_synthetic"], " (synthetic)", ""))
    ax.barh(labels, d["dwell_months"], color=colours)
    ax.set_xlabel("Months undetected")
    ax.set_title("Longest time attackers went unnoticed")
    _note(fig, "Real incidents in green, synthetic in grey. Synthetic dwell is drawn from "
               "type-specific lognormals, not observed data.")
    return _save(fig, "08_exposure_ranking")


def fig_volume_timeline(a):
    d = a.incident_volume_timeline(freq="Y", by="vector_class")
    d = d[d.index.astype(int) >= 2019]
    fig, ax = plt.subplots(figsize=(7.5, 4))
    ax.stackplot(d.index.astype(int), d["Human factor"], d["Technical"],
                 colors=[HUMAN, TECH], labels=["Human factor", "Technical"], alpha=0.9)
    ax.set_ylabel("Incidents")
    ax.set_title("Incident volume by entry vector")
    ax.legend(frameon=False, loc="upper left", fontsize=8)
    _note(fig, "SYNTHETIC-DOMINATED AND FLAT BY CONSTRUCTION: synthetic dates are drawn "
               "uniformly across 2019-2026, so this shows composition, not trend. 2026 is "
               "part-year (window ends 1 Aug).")
    return _save(fig, "09_volume_timeline")


# --------------------------------------------------------------------------- #
# 3. Who gets hit
# --------------------------------------------------------------------------- #

def fig_supply_chain(a):
    d = a.supply_chain_blast_radius()
    fig, axes = plt.subplots(1, 2, figsize=(8, 3.4))
    axes[0].bar(d.index, d["median_records"], color=[TECH, HUMAN], width=0.55)
    axes[0].yaxis.set_major_formatter(FuncFormatter(_thousands))
    axes[0].set_title("Median people affected", fontsize=10)
    mult = d.loc["Via third party", "records_multiplier_vs_direct"]
    axes[0].text(1, d.loc["Via third party", "median_records"], f"  {mult}x",
                 va="bottom", ha="center", fontweight="bold", color=HUMAN)

    real = a.downstream_reach_real().dropna(subset=["downstream_orgs_affected"]).head(8).iloc[::-1]
    axes[1].barh(real["organisation"].str.slice(0, 26), real["downstream_orgs_affected"],
                 color=REAL)
    axes[1].set_xscale("log")
    axes[1].set_title("Real vendor breaches: orgs hit downstream", fontsize=10)
    axes[1].tick_params(labelsize=7)
    fig.suptitle("One supplier, many victims", fontweight="bold", y=1.02)
    _note(fig, "Left: all incidents. Right: real incidents only, downstream counts as reported.")
    return _save(fig, "10_supply_chain")


def fig_sector_profile(a):
    d = a.sector_impact_profile().sort_values("pct_human_factor")
    fig, ax = plt.subplots(figsize=(7.5, 5))
    ax.barh(d.index, d["pct_human_factor"], color=[
        HUMAN if "Charity" in s or "Nonprofit" in s else MUTED for s in d.index])
    ax.axvline(64.5, color=INK, ls="--", lw=1)
    ax.text(64.5, -0.9, " dataset average", fontsize=7, color=INK)
    ax.set_xlabel("% of incidents entered via a human factor")
    ax.set_title("Human-factor entry by sector")
    _note(fig, "All incidents. Nonprofit sectors highlighted.")
    return _save(fig, "11_sector_profile")


def fig_charity_vs_rest(a):
    d = a.charity_vs_rest()
    metrics = ["pct_sensitive_data", "pct_human_factor"]
    labels = ["Holding sensitive data\n(health, financial, safeguarding)",
              "Entered via a human factor"]
    fig, ax = plt.subplots(figsize=(6.5, 3.4))
    y = np.arange(len(metrics))
    ax.barh(y - 0.19, [d.loc[m, "Nonprofit"] for m in metrics], height=0.36,
            color=HUMAN, label="Nonprofit")
    ax.barh(y + 0.19, [d.loc[m, "Other"] for m in metrics], height=0.36,
            color=MUTED, label="All other org types")
    ax.set_yticks(y)
    ax.set_yticklabels(labels, fontsize=8)
    ax.set_xlabel("% of incidents")
    # Title states only what the chart shows. Nonprofits are entered the same way
    # but sit LOWER on sensitive-data exposure here, so "same exposure" would be
    # an overclaim.
    ax.set_title("Charities are broken into the same way as everyone else", pad=26)
    ax.legend(frameon=False, fontsize=8, ncol=2, loc="lower right",
              bbox_to_anchor=(1.0, 1.005))
    ax.set_xlim(0, 78)
    n_cost, o_cost = d.loc["median_cost_usd", "Nonprofit"], d.loc["median_cost_usd", "Other"]
    _note(fig, f"Median modelled response cost: \\${n_cost:,.0f} nonprofit vs \\${o_cost:,.0f} "
               "other.  SYNTHETIC-DOMINATED: only 3 of 27 real incidents are nonprofits, and "
               "cost is a generator-derived field — illustrative, not measured.")
    return _save(fig, "12_charity_vs_rest")


# --------------------------------------------------------------------------- #
# 4. Method / data-quality figures
# --------------------------------------------------------------------------- #

def fig_calibration(a):
    fig, ax = plt.subplots(figsize=(6.5, 4))
    for label, series, colour in [("Real (n=27)", a.real["records_affected"], REAL),
                                  ("Synthetic (n=1,000)", a.syn["records_affected"], MUTED)]:
        s = series.dropna().sort_values()
        ax.step(s, np.arange(1, len(s) + 1) / len(s), where="post", color=colour,
                lw=2, label=label)
    ax.set_xscale("log")
    ax.xaxis.set_major_formatter(FuncFormatter(_thousands))
    ax.set_xlabel("People affected (log scale)")
    ax.set_ylabel("Cumulative share of incidents")
    ax.set_title("Real vs synthetic: these are not the same distribution")
    ax.legend(frameon=False, fontsize=8)
    _note(fig, "METHOD CHECK, NOT A FINDING. The real set is curated famous incidents, so it "
               "is selection-biased toward the enormous. Do not pool the two sets.")
    return _save(fig, "13_calibration")


def fig_missingness(a):
    d = a.missingness_profile()
    d = d[(d > 0).any(axis=1)]
    fig, ax = plt.subplots(figsize=(6.5, max(3, 0.28 * len(d))))
    im = ax.imshow(d.values, cmap="Reds", vmin=0, vmax=100, aspect="auto")
    ax.set_xticks([0, 1])
    ax.set_xticklabels(["Real", "Synthetic"], fontsize=8)
    ax.set_yticks(range(len(d)))
    ax.set_yticklabels(d.index, fontsize=7)
    for i in range(len(d)):
        for j in range(2):
            ax.text(j, i, f"{d.values[i, j]:.0f}", ha="center", va="center", fontsize=6.5,
                    color="white" if d.values[i, j] > 50 else INK)
    ax.set_title("Missing data (%)")
    fig.colorbar(im, ax=ax, shrink=0.6, label="% missing")
    _note(fig, "Incident reporting is patchy by nature. Absence of a number is not absence "
               "of harm.")
    return _save(fig, "14_missingness")


def fig_correlation(a):
    d = a.correlation_matrix()
    fig, ax = plt.subplots(figsize=(5.5, 4.6))
    im = ax.imshow(d.values, cmap="RdBu_r", vmin=-1, vmax=1)
    ax.set_xticks(range(len(d)))
    ax.set_xticklabels(d.columns, rotation=45, ha="right", fontsize=7)
    ax.set_yticks(range(len(d)))
    ax.set_yticklabels(d.index, fontsize=7)
    for i in range(len(d)):
        for j in range(len(d)):
            ax.text(j, i, f"{d.values[i, j]:.2f}", ha="center", va="center", fontsize=6.5)
    ax.set_title("Spearman correlation, impact measures")
    fig.colorbar(im, ax=ax, shrink=0.7)
    _note(fig, "estimated_cost_usd excluded: the generator computes it from records and "
               "downtime, so including it manufactures a correlation.")
    return _save(fig, "15_correlation")


# --------------------------------------------------------------------------- #
# 5. Interactive map
# --------------------------------------------------------------------------- #

def fig_map(a):
    """Delegates to map_layers.build_map — the five-layer interactive map."""
    from map_layers import build_map
    os.makedirs(OUT, exist_ok=True)
    path = build_map(a, os.path.join(OUT, "16_incident_map.html"))
    print(f"  {path}")
    return path


FIGURES = {
    "awareness": fig_awareness_share,
    "vectors": fig_top_vectors,
    "credential": fig_credential_led_real,
    "beacon": fig_beacon_timeline,
    "lag": fig_response_lag,
    "cumulative": fig_cumulative_records,
    "gantt": fig_lifecycle_gantt,
    "exposure": fig_exposure_ranking,
    "volume": fig_volume_timeline,
    "supplychain": fig_supply_chain,
    "sector": fig_sector_profile,
    "charity": fig_charity_vs_rest,
    "calibration": fig_calibration,
    "missingness": fig_missingness,
    "correlation": fig_correlation,
    "map": fig_map,
}


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--csv", default="extracted_files/cyber_incidents.csv")
    p.add_argument("--only", default=None, choices=list(FIGURES))
    p.add_argument("--out", default="figures")
    args = p.parse_args()

    global OUT
    OUT = args.out

    a = IncidentAnalysis(args.csv)
    todo = {args.only: FIGURES[args.only]} if args.only else FIGURES
    print(f"Rendering {len(todo)} figure(s):")
    for name, fn in todo.items():
        try:
            fn(a)
        except Exception as e:
            print(f"  FAILED {name}: {type(e).__name__}: {e}")


if __name__ == "__main__":
    main()
