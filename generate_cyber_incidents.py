#!/usr/bin/env python3
"""
generate_cyber_incidents.py
======

Usage:
    python generate_cyber_incidents.py --rows 1000 --seed 42 --out cyber_incidents.csv
"""

from __future__ import annotations

import argparse
import csv
import random
from dataclasses import dataclass, asdict, fields as dc_fields
from datetime import date, timedelta

from faker import Faker

from geo_reference import CITIES, COUNTRY_META, REAL_HQ
from settlements import place

# --------------------------------------------------------------------------- #
# Schema
# --------------------------------------------------------------------------- #


@dataclass
class Incident:
    incident_id: str
    incident_name: str
    organisation: str
    org_type: str            # private / public / nonprofit / vendor
    sector: str
    country: str
    country_name: str
    region: str
    hq_city: str
    settlement_type: str     # city / town / rural
    hq_lat: str
    hq_lon: str
    victim_scope: str        # local / national / multinational
    data_subject_countries: str  # pipe-delimited ISO2 of where affected people are
    incident_type: str       # ransomware, data breach, BEC, DDoS, ...
    attack_vector: str       # initial access
    threat_actor: str
    threat_actor_type: str   # ransomware crew / nation state / hacktivist / insider / unknown
    supply_chain: bool       # was the victim hit via a third party, or was it the third party?
    downstream_orgs_affected: str   # int, or "" when unknown / not applicable
    date_occurred: str       # ISO date (first intrusione)
    date_discovered: str
    date_disclosed: str
    dwell_time_days: str
    detection_method: str
    records_affected: str
    data_types_exposed: str  # pipe-delimited multi-label
    ransom_demanded_usd: str
    ransom_paid: str         # yes / no / undisclosed / not_applicable
    downtime_days: str
    estimated_cost_usd: str
    regulator_notified: str  # yes / no / unknown
    severity: str            # low / medium / high / critical
    is_synthetic: bool
    source: str              # publisher / primary source for real rows
    notes: str


CSV_COLUMNS = [f.name for f in dc_fields(Incident)]



# 1. Real incidents (public reporting; figures as reported)
REAL_INCIDENTS = [
    # name, org, org_type, sector, country, inc_type, vector, actor, actor_type,
    # supply_chain, downstream, occurred, discovered, disclosed, detection,
    # records, data_types, ransom_demand, ransom_paid, downtime, cost, regulator,
    # severity, source, notes
    ("Beacon CRM supporter-data breach", "Beacon CRM", "vendor", "Nonprofit technology", "GB",
     "Data breach", "Compromised credentials", "Unattributed", "Unknown", True, 1000,
     "2026-07-27", "2026-07-29", "2026-08-03", "Internal detection", "",
     "name|email|postal_address|phone|date_of_birth|gender|donation_history",
     "", "not_applicable", 0, "", "yes", "critical",
     "The Register / BankInfoSecurity / SCVO, Aug 2026",
     "Database backups copied and likely exfiltrated; 1,500+ charity customers told to assume all "
     "stored data taken. Victim count provisional, investigation ongoing. ICO notified."),

    ("Blackbaud ransomware breach", "Blackbaud", "vendor", "Nonprofit technology", "US",
     "Ransomware", "Compromised credentials", "Unattributed", "Ransomware crew", True, 13000,
     "2020-02-07", "2020-05-20", "2020-07-16", "Internal detection", 12000000,
     "name|email|postal_address|donation_history|bank_details|ssn",
     "", "yes", 0, 49500000, "yes", "critical",
     "US multistate AG settlement (Oct 2023); ICO/FTC actions",
     "Canonical charity-CRM precedent. Ransom paid for deletion assurance. $49.5M multistate "
     "settlement. Records figure is an estimate across downstream customers."),

    ("MOVEit Transfer mass exploitation", "Progress Software (MOVEit)", "vendor", "Software", "US",
     "Data breach", "Zero-day exploit (CVE-2023-34362)", "Cl0p", "Ransomware crew", True, 2770,
     "2023-05-27", "2023-05-31", "2023-06-05", "Vendor disclosure", 95000000,
     "name|email|postal_address|ssn|financial|health", "", "no", 0, "", "yes", "critical",
     "Emsisoft MOVEit tracker; CISA advisory AA23-158A",
     "Largest single supply-chain data-theft event on record by downstream org count."),

    ("Change Healthcare ransomware", "Change Healthcare (UnitedHealth)", "private", "Healthcare", "US",
     "Ransomware", "Compromised credentials (no MFA)", "ALPHV/BlackCat", "Ransomware crew", False, "",
     "2024-02-12", "2024-02-21", "2024-02-22", "Internal detection", 190000000,
     "name|postal_address|ssn|health|insurance|financial", 22000000, "yes", 30, 2900000000,
     "yes", "critical", "UnitedHealth Group filings; HHS OCR",
     "Largest US healthcare breach by individuals affected. Citrix portal without MFA."),

    ("British Library ransomware", "British Library", "public", "Culture/Library", "GB",
     "Ransomware", "Compromised credentials", "Rhysida", "Ransomware crew", False, "",
     "2023-10-25", "2023-10-28", "2023-10-28", "Internal detection", 600000,
     "name|email|internal_hr|financial", 750000, "no", 300, 8000000, "yes", "critical",
     "British Library Learning Lessons report (Mar 2024)",
     "Public-sector body, no ransom paid, ~£6-7M rebuild. Excellent post-incident report."),

    ("ICRC humanitarian data breach", "International Committee of the Red Cross", "nonprofit",
     "Humanitarian", "CH", "Data breach", "Unpatched vulnerability (CVE-2021-40539)",
     "Unattributed (suspected state-linked)", "Nation state", True, 60,
     "2021-11-09", "2022-01-18", "2022-01-19", "Third-party notification", 515000,
     "name|postal_address|family_links|vulnerable_persons", "", "not_applicable", 0, "", "no",
     "critical", "ICRC statements, Jan-Feb 2022",
     "Restoring Family Links data on missing persons, detainees and refugees. Highest-harm "
     "nonprofit breach in the reference set."),

    ("Synnovis pathology ransomware", "Synnovis", "vendor", "Healthcare", "GB",
     "Ransomware", "Compromised credentials", "Qilin", "Ransomware crew", True, 2,
     "2024-06-03", "2024-06-03", "2024-06-04", "Internal detection", 900000,
     "name|health|test_results|nhs_number", 50000000, "no", 90, "", "yes", "critical",
     "NHS England statements; BBC, Jun 2024",
     "Downstream: Guy's & St Thomas' and King's College NHS trusts; thousands of procedures cancelled."),

    ("Capita cyber incident", "Capita", "private", "Outsourcing/BPO", "GB",
     "Ransomware", "Phishing / malicious download", "Black Basta", "Ransomware crew", True, 90,
     "2023-03-22", "2023-03-31", "2023-04-03", "Internal detection", 6600000,
     "name|postal_address|pension|ni_number|bank_details", "", "no", 14, 33000000, "yes",
     "critical", "Capita statements; ICO investigation",
     "Pension scheme data for hundreds of downstream clients; separate exposed-AWS-bucket incident."),

    ("Advanced NHS 111 outage", "Advanced (Adastra)", "vendor", "Healthcare", "GB",
     "Ransomware", "Compromised credentials (no MFA)", "LockBit", "Ransomware crew", True, 80,
     "2022-08-04", "2022-08-04", "2022-08-05", "Internal detection", 82946,
     "name|health|care_plans", "", "no", 84, "", "yes", "high",
     "ICO fine notice (Mar 2025), £3.07M",
     "ICO cited absent MFA on a customer-facing remote access portal."),

    ("SolarWinds Orion supply-chain compromise", "SolarWinds", "vendor", "Software", "US",
     "Supply chain compromise", "Trojanised software update", "APT29 (Cozy Bear/Nobelium)",
     "Nation state", True, 18000, "2019-09-04", "2020-12-08", "2020-12-13",
     "Third-party notification", "", "internal_email|source_code|government_systems", "",
     "not_applicable", 0, 40000000, "yes", "critical", "CISA ED 21-01; SolarWinds SEC filings",
     "~14 months dwell time before FireEye discovery."),

    ("Kaseya VSA supply-chain ransomware", "Kaseya", "vendor", "Software", "US",
     "Ransomware", "Zero-day exploit (CVE-2021-30116)", "REvil/Sodinokibi", "Ransomware crew",
     True, 1500, "2021-07-02", "2021-07-02", "2021-07-02", "Third-party notification", "",
     "encrypted_systems", 70000000, "no", 10, "", "yes", "critical",
     "CISA advisory AA21-183A; Kaseya statements",
     "MSP tooling abused to reach ~1,500 downstream SMEs in one afternoon."),

    ("Colonial Pipeline ransomware", "Colonial Pipeline", "private", "Energy", "US",
     "Ransomware", "Compromised credentials (legacy VPN, no MFA)", "DarkSide", "Ransomware crew",
     False, "", "2021-04-29", "2021-05-07", "2021-05-08", "Internal detection", "",
     "internal_data", 4400000, "yes", 6, "", "yes", "critical",
     "US DOJ; congressional testimony, Jun 2021",
     "~$2.3M of the ransom later recovered by DOJ."),

    ("Equifax data breach", "Equifax", "private", "Financial services", "US",
     "Data breach", "Unpatched vulnerability (CVE-2017-5638)", "Unattributed (US DOJ indicted PLA members)",
     "Nation state", False, "", "2017-05-13", "2017-07-29", "2017-09-07", "Internal detection",
     147900000, "name|ssn|date_of_birth|postal_address|drivers_licence|credit_card",
     "", "not_applicable", 0, 1400000000, "yes", "critical",
     "FTC settlement (Jul 2019); US House Oversight report",
     "76 days undetected; expired cert on inspection tooling delayed detection."),

    ("Target POS breach", "Target", "private", "Retail", "US",
     "Data breach", "Third-party supplier credentials", "Unattributed", "Financially motivated",
     True, "", "2013-11-27", "2013-12-12", "2013-12-19", "Law enforcement notification",
     110000000, "credit_card|name|email|phone|postal_address", "", "not_applicable", 0,
     292000000, "yes", "critical", "Target 10-K filings; US Senate Commerce report",
     "Initial access via an HVAC contractor's credentials — classic third-party pivot."),

    ("Maersk NotPetya destruction", "A.P. Moller-Maersk", "private", "Logistics", "DK",
     "Destructive malware", "Trojanised software update (M.E.Doc)", "Sandworm", "Nation state",
     True, "", "2017-06-27", "2017-06-27", "2017-06-28", "Internal detection", "",
     "not_applicable", "", "not_applicable", 10, 300000000, "no", "critical",
     "Maersk statements; UK NCSC attribution (Feb 2018)",
     "Collateral damage from a Ukraine-targeted wiper; ~4,000 servers rebuilt in 10 days."),

    ("MGM Resorts social-engineering attack", "MGM Resorts International", "private", "Hospitality", "US",
     "Ransomware", "Vishing / help-desk social engineering", "Scattered Spider + ALPHV",
     "Ransomware crew", False, "", "2023-09-08", "2023-09-10", "2023-09-11", "Internal detection",
     10600000, "name|postal_address|date_of_birth|drivers_licence|ssn", "", "no", 10, 100000000,
     "yes", "high", "MGM 8-K filings, Oct 2023",
     "Help-desk identity verification bypassed by phone."),

    ("M&S / Co-op retail intrusions", "Marks & Spencer", "private", "Retail", "GB",
     "Ransomware", "Help-desk social engineering (via IT supplier)", "Scattered Spider + DragonForce",
     "Ransomware crew", True, "", "2025-04-17", "2025-04-22", "2025-04-22", "Internal detection",
     "", "name|email|postal_address|phone|date_of_birth|order_history", "", "no", 46, 400000000,
     "yes", "critical", "M&S RNS statements; UK NCSC guidance (May 2025)",
     "Online ordering suspended ~7 weeks; ~£300M profit impact guided."),

    ("Snowflake customer-tenant data theft", "Snowflake customers (Ticketmaster et al.)", "vendor",
     "Cloud/SaaS", "US", "Data breach", "Credential stuffing (infostealer creds, no MFA)",
     "ShinyHunters / UNC5537", "Financially motivated", True, 165,
     "2024-04-14", "2024-05-23", "2024-05-31", "Third-party notification", 560000000,
     "name|email|phone|postal_address|partial_payment_card", 500000, "no", 0, "", "yes",
     "critical", "Mandiant UNC5537 report (Jun 2024)",
     "Not a platform breach — customer tenants without MFA. Directly analogous to CRM tenant risk."),

    ("23andMe credential stuffing", "23andMe", "private", "Biotech/Consumer", "US",
     "Data breach", "Credential stuffing", "Unattributed", "Financially motivated", False, "",
     "2023-04-01", "2023-10-06", "2023-10-06", "Public leak / dark web", 6900000,
     "name|date_of_birth|ancestry|genetic_relatives|postal_address", "", "not_applicable", 0,
     30000000, "yes", "high", "ICO/OPC joint investigation (Jun 2025); 23andMe filings",
     "Reused passwords; relatives feature amplified 14k compromised accounts to 6.9M people."),

    ("Okta support case-file breach", "Okta", "vendor", "Identity/SaaS", "US",
     "Data breach", "Compromised credentials (service account)", "Unattributed", "Unknown", True, 134,
     "2023-09-28", "2023-10-02", "2023-10-20", "Third-party notification", "",
     "session_tokens|support_case_files", "", "not_applicable", 0, "", "yes", "high",
     "Okta security incident updates, Oct-Nov 2023",
     "Customer flagged it before the vendor confirmed — detection-gap case study."),

    ("Uber MFA-fatigue intrusion", "Uber", "private", "Technology", "US",
     "Unauthorised access", "MFA fatigue / social engineering", "Lapsus$-linked actor",
     "Financially motivated", False, "", "2022-09-15", "2022-09-15", "2022-09-16",
     "Internal detection", "", "internal_systems|source_code", "", "not_applicable", 1, "",
     "yes", "medium", "Uber security update, Sep 2022",
     "Hardcoded admin credentials in a PowerShell script enabled privilege escalation."),

    ("Optus customer data breach", "Optus", "private", "Telecoms", "AU",
     "Data breach", "Unauthenticated public API endpoint", "Unattributed", "Financially motivated",
     False, "", "2022-09-17", "2022-09-21", "2022-09-22", "Internal detection", 9800000,
     "name|date_of_birth|email|phone|passport|drivers_licence", 1000000, "no", 0, 140000000,
     "yes", "critical", "OAIC proceedings; Australian Senate inquiry",
     "No authentication on an internet-facing API — the cheapest possible root cause."),

    ("Medibank data breach", "Medibank", "private", "Insurance/Health", "AU",
     "Data breach", "Compromised credentials (contractor, no MFA)", "REvil-linked actor",
     "Ransomware crew", True, "", "2022-08-12", "2022-10-12", "2022-10-13",
     "Internal detection", 9700000, "name|date_of_birth|health|claims|passport", 10000000, "no",
     0, 80000000, "yes", "critical", "OAIC civil proceedings (Jun 2023)",
     "Refused to pay; attackers published sensitive health records including terminations."),

    ("Rackspace Hosted Exchange ransomware", "Rackspace", "vendor", "Cloud/Hosting", "US",
     "Ransomware", "Unpatched vulnerability (ProxyNotShell/OWASSRF)", "Play", "Ransomware crew",
     True, 30000, "2022-11-30", "2022-12-02", "2022-12-06", "Internal detection", "",
     "email_mailboxes", "", "no", 30, 30000000, "yes", "high",
     "Rackspace incident reports, Dec 2022",
     "Hosted Exchange permanently retired after the incident."),

    ("SEPA ransomware and data leak", "Scottish Environment Protection Agency", "public",
     "Government/Environment", "GB", "Ransomware", "Phishing", "Conti", "Ransomware crew", False,
     "", "2020-12-24", "2020-12-24", "2021-01-14", "Internal detection", "",
     "contracts|procurement|internal_staff|project_data", "", "no", 120, 1400000, "yes", "high",
     "SEPA/Audit Scotland lessons-learned reports (2021)",
     "4,000+ files leaked; refused to pay; multi-year recovery. Public-sector analogue to a "
     "small charity with thin IT."),

    ("Redcar & Cleveland Council attack", "Redcar & Cleveland Borough Council", "public",
     "Local government", "GB", "Ransomware", "Phishing", "Unattributed", "Ransomware crew", False,
     "", "2020-02-08", "2020-02-08", "2020-02-10", "Internal detection", "", "council_services",
     "", "no", 135, 10400000, "yes", "high", "UK MHCLG/council statements (2020)",
     "135,000 residents offline for weeks; ~£10.4M recovery on a small council budget."),

    ("Save the Children BEC fraud", "Save the Children Federation", "nonprofit", "Humanitarian", "US",
     "Business email compromise", "Phishing / email account takeover", "Unattributed",
     "Financially motivated", False, "", "2017-04-01", "2017-05-01", "2018-12-19",
     "Internal detection", "", "not_applicable", "", "not_applicable", 0, 1000000, "no",
     "medium", "Save the Children IRS Form 990 (FY2017); Boston Globe, Dec 2018",
     "Fake invoices for solar panels routed ~$1M to a fraudulent account. Charity BEC baseline."),
]
# fmt: on


def build_real_incidents() -> list[Incident]:
    out: list[Incident] = []
    
    # Uterates through each real incident and indexes them
    for i, row in enumerate(REAL_INCIDENTS, start=1):
        (name, org, org_type, sector, country, inc_type, vector, actor, actor_type,
         supply_chain, downstream, occurred, discovered, disclosed, detection, records,
         data_types, ransom_demand, ransom_paid, downtime, cost, regulator, severity,
         source, notes) = row

        # Converts date occurred and discovered into time format
        d_occ = date.fromisoformat(occurred)
        d_dis = date.fromisoformat(discovered)
        
        # Uses the REAL_HQ dictionary to get the headquarters information for the organisation, or defaults to unknown values if not found
        city, lat, lon, scope, subjects = REAL_HQ.get(
            org, ("", float("nan"), float("nan"), "unknown", country))
        
        # Gets the country metadata from country meta dictionary
        meta = COUNTRY_META.get(country, (country, "Unknown"))

        # Fills in the records based on the metadata.
        out.append(
            Incident(
                incident_id=f"REAL-{i:04d}",
                incident_name=name,
                organisation=org,
                org_type=org_type,
                sector=sector,
                country=country,
                country_name=meta[0],
                region=meta[1],
                hq_city=city,
                settlement_type="city",
                hq_lat=str(lat),
                hq_lon=str(lon),
                victim_scope=scope,
                data_subject_countries=subjects,
                incident_type=inc_type,
                attack_vector=vector,
                threat_actor=actor,
                threat_actor_type=actor_type,
                supply_chain=supply_chain,
                downstream_orgs_affected=str(downstream),
                date_occurred=occurred,
                date_discovered=discovered,
                date_disclosed=disclosed,
                dwell_time_days=str((d_dis - d_occ).days),
                detection_method=detection,
                records_affected=str(records),
                data_types_exposed=data_types,
                ransom_demanded_usd=str(ransom_demand),
                ransom_paid=ransom_paid,
                downtime_days=str(downtime),
                estimated_cost_usd=str(cost),
                regulator_notified=regulator,
                severity=severity,
                is_synthetic=False,
                source=source,
                notes=notes,
            )
        )
    return out

### Synthetic generator ###

SECTORS = {
    # sector: (weight, org_type, typical log10 records mean, regulator-heavy?)
    "Charity/Nonprofit":      (0.13, "nonprofit", 4.0, True),
    "Nonprofit technology":   (0.05, "vendor",    5.3, True),
    "Healthcare":             (0.11, "private",   5.0, True),
    "Education":              (0.08, "public",    4.4, True),
    "Local government":       (0.07, "public",    4.3, True),
    "Financial services":     (0.10, "private",   5.2, True),
    "Retail":                 (0.09, "private",   5.4, True),
    "Manufacturing":          (0.08, "private",   3.6, False),
    "Software":               (0.07, "vendor",    5.0, False),
    "Cloud/SaaS":             (0.06, "vendor",    5.5, False),
    "Logistics":              (0.05, "private",   3.9, False),
    "Energy/Utilities":       (0.04, "public",    3.8, True),
    "Hospitality":            (0.04, "private",   4.8, False),
    "Legal/Professional":     (0.03, "private",   4.0, True),
}


# Adds weights to each country based on the likelihood of incidents occurring there
COUNTRIES = {"GB": 0.26, "US": 0.24, "IE": 0.03, "AU": 0.05, "CA": 0.04, "DE": 0.05,
             "FR": 0.04, "NL": 0.03, "IN": 0.04, "SG": 0.02, "NZ": 0.02, "CH": 0.02,
             "ES": 0.02, "IT": 0.02, "SE": 0.02, "NO": 0.01, "DK": 0.01, "PL": 0.02,
             "JP": 0.02, "KR": 0.01, "AE": 0.01, "ZA": 0.01, "KE": 0.01, "NG": 0.01,
             "BR": 0.01, "MX": 0.01}

# Scope of who is affected, conditioned on org type. Vendors and private firms
# spill across borders far more often than a local council or a small charity.
VICTIM_SCOPE = {
    "nonprofit": {"local": 0.35, "national": 0.55, "multinational": 0.10},
    "public":    {"local": 0.45, "national": 0.53, "multinational": 0.02},
    "private":   {"local": 0.15, "national": 0.55, "multinational": 0.30},
    "vendor":    {"local": 0.05, "national": 0.40, "multinational": 0.55},
}

# Weights for different incident types
INCIDENT_TYPES = {
    "Ransomware": 0.30,
    "Data breach": 0.28,
    "Business email compromise": 0.11,
    "Unauthorised access": 0.10,
    "Supply chain compromise": 0.07,
    "Phishing campaign": 0.06,
    "Insider incident": 0.04,
    "DDoS": 0.03,
    "Destructive malware": 0.01,
}

# Initial-access vectors conditioned on incident type and their weights
VECTORS_BY_TYPE = {
    "Ransomware": {"Compromised credentials": 0.30, "Phishing": 0.22,
                   "Unpatched vulnerability": 0.20, "Exposed RDP/VPN": 0.16,
                   "Help-desk social engineering": 0.07, "Third-party supplier access": 0.05},
    "Data breach": {"Compromised credentials": 0.24, "Credential stuffing": 0.15,
                    "Misconfigured cloud storage": 0.15, "Unpatched vulnerability": 0.14,
                    "Insecure API endpoint": 0.12, "Phishing": 0.11,
                    "Third-party supplier access": 0.09},
    "Business email compromise": {"Phishing": 0.55, "Compromised credentials": 0.30,
                                  "MFA fatigue": 0.15},
    "Unauthorised access": {"Compromised credentials": 0.35, "MFA fatigue": 0.20,
                            "Exposed RDP/VPN": 0.18, "Insecure API endpoint": 0.14,
                            "Help-desk social engineering": 0.13},
    "Supply chain compromise": {"Trojanised software update": 0.40,
                                "Third-party supplier access": 0.35,
                                "Compromised credentials": 0.15,
                                "Malicious dependency": 0.10},
    "Phishing campaign": {"Phishing": 1.0},
    "Insider incident": {"Malicious insider": 0.55, "Negligent insider": 0.45},
    "DDoS": {"Volumetric flood": 0.70, "Application-layer flood": 0.30},
    "Destructive malware": {"Trojanised software update": 0.45, "Phishing": 0.30,
                            "Unpatched vulnerability": 0.25},
}

# The type of actors or weights
ACTOR_TYPES = {
    "Ransomware crew": 0.42, "Financially motivated": 0.24, "Unknown": 0.16,
    "Nation state": 0.09, "Hacktivist": 0.05, "Insider": 0.04,
}

# Different crews that are used to generate incidents
FAKE_CREWS = ["PaleHydra", "CobaltFinch", "GlassMantis", "RustVulture", "NineSpindle",
              "ObsidianKoi", "TinCathedral", "SlateWarden", "HollowLantern", "DimStag",
              "AmberBastion", "QuietFathom", "IronMagpie", "VelvetSiphon", "NorthQuarry"]

# Detection methods and their weights
DETECTION = {"Internal detection": 0.34, "Third-party notification": 0.20,
             "Security vendor / MDR": 0.14, "Law enforcement notification": 0.09,
             "Customer report": 0.09, "Public leak / dark web": 0.08,
             "Routine audit": 0.06}

DATA_TYPES = ["name", "email", "phone", "postal_address", "date_of_birth", "ssn_or_ni_number",
              "bank_details", "credit_card", "health", "donation_history", "employment",
              "passport", "safeguarding_notes", "internal_email", "credentials"]

CHARITY_CAUSES = ["Trust", "Foundation", "Appeal", "Alliance", "Aid", "Support", "Care",
                  "Network", "Fund", "Society"]
CHARITY_THEMES = ["Hospice", "Rivers", "Youth", "Literacy", "Shelter", "Refuge", "Heritage",
                  "Wellbeing", "Mobility", "Harvest", "Lantern", "Meadow", "Beacon Hill",
                  "Wayfarer", "Kindling"]


def weighted(d: dict, rng: random.Random):
    return rng.choices(list(d.keys()), weights=list(d.values()), k=1)[0]


def org_name(sector: str, org_type: str, fake: Faker, rng: random.Random) -> str:
    if org_type == "nonprofit":
        return f"{rng.choice(CHARITY_THEMES)} {rng.choice(CHARITY_CAUSES)}"
    if org_type == "public":
        return f"{fake.city()} {rng.choice(['Council', 'Authority', 'NHS Trust', 'District Board'])}"
    return fake.company()


def lognormal_int(rng: random.Random, log10_mean: float, log10_sd: float = 0.85) -> int:
    return max(1, int(10 ** rng.gauss(log10_mean, log10_sd)))


def make_synthetic(idx: int, fake: Faker, rng: random.Random,
                   start: date, end: date) -> Incident:
    sector = rng.choices(list(SECTORS), weights=[v[0] for v in SECTORS.values()], k=1)[0]
    _, org_type, rec_mu, reg_heavy = SECTORS[sector]

    inc_type = weighted(INCIDENT_TYPES, rng)
    vector = weighted(VECTORS_BY_TYPE[inc_type], rng)
    actor_type = weighted(ACTOR_TYPES, rng)
    if inc_type == "Ransomware":
        actor_type = "Ransomware crew"
    if inc_type == "Insider incident":
        actor_type = "Insider"

    named = actor_type in ("Ransomware crew", "Nation state") and rng.random() < 0.75
    actor = rng.choice(FAKE_CREWS) if named else "Unattributed"

    supply_chain = (
        inc_type == "Supply chain compromise"
        or vector in ("Third-party supplier access", "Trojanised software update",
                      "Malicious dependency")
        or (org_type == "vendor" and rng.random() < 0.45)
    )
    downstream = ""
    if supply_chain:
        downstream = str(lognormal_int(rng, 1.6 if org_type != "vendor" else 2.4, 0.7))

    # --- timeline ---------------------------------------------------------- #
    span = (end - start).days
    d_occ = start + timedelta(days=rng.randint(0, span))

    if inc_type in ("Ransomware", "DDoS", "Destructive malware"):
        dwell = max(0, int(rng.lognormvariate(1.1, 0.9)))          # loud, found fast
    elif inc_type == "Supply chain compromise":
        dwell = max(1, int(rng.lognormvariate(4.4, 0.9)))          # quiet, found late
    elif inc_type == "Insider incident":
        dwell = max(0, int(rng.lognormvariate(3.6, 1.0)))
    else:
        dwell = max(0, int(rng.lognormvariate(3.3, 1.1)))
    dwell = min(dwell, 900)

    # Right-censor at the window end: an incident cannot be discovered or
    # disclosed after the dataset's own cut-off. Without this, a long-dwell
    # intrusion drawn near the end spills into a stray future period and shows
    # up as a phantom tick on every timeline chart.
    d_disc = min(d_occ + timedelta(days=dwell), end)
    dwell = (d_disc - d_occ).days

    disclose_lag = max(0, int(rng.lognormvariate(1.8, 0.9)))
    if reg_heavy:
        disclose_lag = min(disclose_lag, 72)
    d_disclosed = min(d_disc + timedelta(days=min(disclose_lag, 400)), end)

    # --- impact ------------------------------------------------------------ #
    if inc_type in ("DDoS", "Business email compromise", "Destructive malware"):
        records = "" if rng.random() < 0.8 else str(lognormal_int(rng, rec_mu - 1.5))
    else:
        r = lognormal_int(rng, rec_mu)
        if supply_chain:
            r = int(r * rng.uniform(2, 12))
        records = str(r)

    n_types = rng.randint(2, 7)
    weights = [4 if t in ("name", "email", "phone", "postal_address") else 1 for t in DATA_TYPES]
    picked = set()
    while len(picked) < n_types:
        picked.add(rng.choices(DATA_TYPES, weights=weights, k=1)[0])
    if sector in ("Charity/Nonprofit", "Nonprofit technology") and rng.random() < 0.55:
        picked.add("donation_history")
    if sector == "Healthcare":
        picked.add("health")
    data_types = "|".join(sorted(picked)) if records != "" else "not_applicable"

    # ransom + downtime + cost
    if inc_type in ("Ransomware", "Destructive malware"):
        ransom = lognormal_int(rng, rng.uniform(5.0, 6.8), 0.5)
        paid = rng.choices(["no", "yes", "undisclosed"], weights=[0.62, 0.20, 0.18], k=1)[0]
        downtime = max(1, int(rng.lognormvariate(2.5, 1.0)))
    elif inc_type == "DDoS":
        ransom, paid = "", "not_applicable"
        downtime = max(1, int(rng.lognormvariate(0.3, 0.8)))
    else:
        ransom = lognormal_int(rng, 5.4, 0.5) if rng.random() < 0.12 else ""
        paid = "not_applicable" if ransom == "" else rng.choice(["no", "undisclosed"])
        downtime = 0 if rng.random() < 0.6 else max(1, int(rng.lognormvariate(1.0, 0.9)))
    downtime = min(downtime, 400)

    rec_n = int(records) if records else 0
    cost = (rec_n * rng.uniform(20, 180)) + (downtime * rng.uniform(4_000, 90_000)) + \
           rng.uniform(25_000, 400_000)
    if org_type == "nonprofit":
        cost *= 0.45   # smaller balance sheets, cheaper (and thinner) response
    cost = "" if rng.random() < 0.22 else str(int(cost))   # real datasets have gaps

    regulator = "yes" if (records and (reg_heavy or rng.random() < 0.6)) else \
                rng.choices(["no", "unknown"], weights=[0.6, 0.4], k=1)[0]

    score = (
        (2 if rec_n > 1_000_000 else 1 if rec_n > 10_000 else 0)
        + (2 if downtime > 30 else 1 if downtime > 5 else 0)
        + (1 if supply_chain else 0)
        + (1 if {"health", "safeguarding_notes", "ssn_or_ni_number", "bank_details"} & picked else 0)
    )
    severity = "critical" if score >= 5 else "high" if score >= 3 else \
               "medium" if score >= 1 else "low"

    org = org_name(sector, org_type, fake, rng)

    # --- geography --------------------------------------------------------- #
    country = weighted(COUNTRIES, rng)
    meta = COUNTRY_META[country]
    # Settlement-aware placement: city / town / rural, weighted by org type, so
    # 30k rows spread across a country instead of stacking on ~71 metro anchors.
    # Coordinates are fictional placements, not claims about a real location.
    settlement, city, lat, lon = place(country, org_type, rng)

    scope = weighted(VICTIM_SCOPE[org_type], rng)
    if supply_chain and rng.random() < 0.5:
        scope = "multinational"          # vendor compromise rarely stops at a border
    if scope == "multinational":
        pool = [c for c in COUNTRIES if c != country]
        extra = rng.sample(pool, k=rng.randint(2, 6))
        subjects = "|".join([country] + sorted(extra))
    else:
        subjects = country

    return Incident(
        incident_id=f"SYN-{idx:05d}",
        incident_name=f"{inc_type} at {org}"[:120],
        organisation=org,
        org_type=org_type,
        sector=sector,
        country=country,
        country_name=meta[0],
        region=meta[1],
        hq_city=city,
        settlement_type=settlement,
        hq_lat=str(lat),
        hq_lon=str(lon),
        victim_scope=scope,
        data_subject_countries=subjects,
        incident_type=inc_type,
        attack_vector=vector,
        threat_actor=actor,
        threat_actor_type=actor_type,
        supply_chain=supply_chain,
        downstream_orgs_affected=downstream,
        date_occurred=d_occ.isoformat(),
        date_discovered=d_disc.isoformat(),
        date_disclosed=d_disclosed.isoformat(),
        dwell_time_days=str(dwell),
        detection_method=weighted(DETECTION, rng),
        records_affected=records,
        data_types_exposed=data_types,
        ransom_demanded_usd=str(ransom),
        ransom_paid=paid,
        downtime_days=str(downtime),
        estimated_cost_usd=cost,
        regulator_notified=regulator,
        severity=severity,
        is_synthetic=True,
        source="synthetic (Faker)",
        notes="",
    )


# --------------------------------------------------------------------------- #
# 3. CLI
# --------------------------------------------------------------------------- #

def main() -> None:
    p = argparse.ArgumentParser(description="Generate a mixed real/synthetic cyber-incident CSV.")
    p.add_argument("--rows", type=int, default=1000, help="number of synthetic rows")
    p.add_argument("--seed", type=int, default=42, help="RNG seed for reproducibility")
    p.add_argument("--out", default="cyber_incidents.csv", help="output CSV path")
    p.add_argument("--start", default="2019-01-01", help="earliest synthetic incident date")
    p.add_argument("--end", default="2026-08-01", help="latest synthetic incident date")
    p.add_argument("--no-real", action="store_true", help="exclude the curated real incidents")
    args = p.parse_args()

    rng = random.Random(args.seed)
    fake = Faker(["en_GB", "en_US"])
    Faker.seed(args.seed)

    rows: list[Incident] = [] if args.no_real else build_real_incidents()
    start, end = date.fromisoformat(args.start), date.fromisoformat(args.end)
    rows += [make_synthetic(i, fake, rng, start, end) for i in range(1, args.rows + 1)]
    rows.sort(key=lambda r: r.date_discovered)

    with open(args.out, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=CSV_COLUMNS)
        w.writeheader()
        for r in rows:
            w.writerow(asdict(r))

    real_n = sum(1 for r in rows if not r.is_synthetic)
    print(f"Wrote {len(rows)} rows to {args.out} ({real_n} real, {len(rows) - real_n} synthetic)")


if __name__ == "__main__":
    main()
