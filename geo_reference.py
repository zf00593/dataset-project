"""
geo_reference.py
================

Geography reference data for the incident dataset.

A cyber incident does not have one location. There are at least four:

  1. where the victim organisation is headquartered   -> hq_country / hq_lat / hq_lon
  2. where the affected people live                   -> data_subject_countries
  3. where the infrastructure sat                     -> not modelled (rarely reported)
  4. where the attacker operated from                 -> not modelled (attribution is
     contested, and plotting an arrow from a country to a victim implies a
     confidence that public reporting almost never supports)

Only 1 and 2 are represented, deliberately. If you map only HQ you will plot
Change Healthcare as a single dot in Tennessee and hide 190 million Americans;
if you map only data subjects you lose the vendor-concentration story. You need
both layers, and they answer different questions.

Coordinates are city centroids, accurate to roughly the city. They are for
choropleth and bubble placement, not for anything that implies a street address.
Populations are approximate mid-2020s figures, used only for per-capita
normalisation on maps.
"""

from __future__ import annotations

# iso2: (name, region, subregion, centroid_lat, centroid_lon, population_millions)
COUNTRY_META = {
    "GB": ("United Kingdom", "Europe", "Northern Europe", 54.00, -2.00, 68.3),
    "IE": ("Ireland", "Europe", "Northern Europe", 53.10, -7.70, 5.3),
    "US": ("United States", "Americas", "North America", 39.50, -98.35, 335.0),
    "CA": ("Canada", "Americas", "North America", 56.10, -106.35, 40.1),
    "AU": ("Australia", "Oceania", "Australia/NZ", -25.30, 133.80, 26.6),
    "NZ": ("New Zealand", "Oceania", "Australia/NZ", -41.50, 172.80, 5.2),
    "DE": ("Germany", "Europe", "Western Europe", 51.17, 10.45, 84.5),
    "FR": ("France", "Europe", "Western Europe", 46.60, 2.20, 68.2),
    "NL": ("Netherlands", "Europe", "Western Europe", 52.13, 5.29, 17.9),
    "CH": ("Switzerland", "Europe", "Western Europe", 46.82, 8.23, 8.9),
    "ES": ("Spain", "Europe", "Southern Europe", 40.46, -3.75, 48.4),
    "IT": ("Italy", "Europe", "Southern Europe", 41.87, 12.57, 58.9),
    "SE": ("Sweden", "Europe", "Northern Europe", 60.13, 18.64, 10.5),
    "NO": ("Norway", "Europe", "Northern Europe", 60.47, 8.47, 5.5),
    "DK": ("Denmark", "Europe", "Northern Europe", 56.26, 9.50, 5.9),
    "PL": ("Poland", "Europe", "Eastern Europe", 51.92, 19.15, 36.7),
    "IN": ("India", "Asia", "Southern Asia", 20.59, 78.96, 1428.0),
    "SG": ("Singapore", "Asia", "South-Eastern Asia", 1.35, 103.82, 5.9),
    "JP": ("Japan", "Asia", "Eastern Asia", 36.20, 138.25, 124.5),
    "KR": ("South Korea", "Asia", "Eastern Asia", 35.91, 127.77, 51.7),
    "AE": ("United Arab Emirates", "Asia", "Western Asia", 23.42, 53.85, 9.5),
    "ZA": ("South Africa", "Africa", "Southern Africa", -30.56, 22.94, 60.4),
    "KE": ("Kenya", "Africa", "Eastern Africa", -0.02, 37.91, 55.1),
    "NG": ("Nigeria", "Africa", "Western Africa", 9.08, 8.68, 223.8),
    "BR": ("Brazil", "Americas", "South America", -14.24, -51.93, 216.4),
    "MX": ("Mexico", "Americas", "Central America", 23.63, -102.55, 128.5),
}

# Plausible HQ cities per country, for jittered bubble placement on maps.
# (city, lat, lon)
CITIES = {
    "GB": [("London", 51.507, -0.128), ("Manchester", 53.480, -2.242),
           ("Birmingham", 52.489, -1.898), ("Leeds", 53.801, -1.549),
           ("Glasgow", 55.864, -4.252), ("Edinburgh", 55.953, -3.189),
           ("Bristol", 51.455, -2.588), ("Cardiff", 51.481, -3.179),
           ("Belfast", 54.597, -5.930), ("Leicester", 52.637, -1.139)],
    "IE": [("Dublin", 53.350, -6.260), ("Cork", 51.898, -8.475)],
    "US": [("New York", 40.713, -74.006), ("Chicago", 41.878, -87.630),
           ("Atlanta", 33.749, -84.388), ("Austin", 30.267, -97.743),
           ("San Francisco", 37.775, -122.419), ("Boston", 42.360, -71.059),
           ("Denver", 39.739, -104.990), ("Seattle", 47.606, -122.332),
           ("Nashville", 36.163, -86.781), ("Minneapolis", 44.978, -93.265)],
    "CA": [("Toronto", 43.653, -79.383), ("Vancouver", 49.283, -123.121),
           ("Montreal", 45.502, -73.567), ("Ottawa", 45.421, -75.697)],
    "AU": [("Sydney", -33.869, 151.209), ("Melbourne", -37.814, 144.963),
           ("Brisbane", -27.470, 153.021), ("Perth", -31.951, 115.861)],
    "NZ": [("Auckland", -36.848, 174.763), ("Wellington", -41.287, 174.776)],
    "DE": [("Berlin", 52.520, 13.405), ("Munich", 48.135, 11.582),
           ("Hamburg", 53.551, 9.993), ("Frankfurt", 50.110, 8.682)],
    "FR": [("Paris", 48.857, 2.352), ("Lyon", 45.764, 4.836),
           ("Toulouse", 43.605, 1.444)],
    "NL": [("Amsterdam", 52.370, 4.895), ("Rotterdam", 51.924, 4.478),
           ("Utrecht", 52.091, 5.122)],
    "CH": [("Zurich", 47.377, 8.542), ("Geneva", 46.204, 6.143)],
    "ES": [("Madrid", 40.417, -3.704), ("Barcelona", 41.385, 2.173)],
    "IT": [("Milan", 45.464, 9.190), ("Rome", 41.903, 12.496)],
    "SE": [("Stockholm", 59.329, 18.069), ("Gothenburg", 57.709, 11.974)],
    "NO": [("Oslo", 59.914, 10.752)],
    "DK": [("Copenhagen", 55.677, 12.569)],
    "PL": [("Warsaw", 52.230, 21.012), ("Krakow", 50.065, 19.945)],
    "IN": [("Mumbai", 19.076, 72.878), ("Bengaluru", 12.972, 77.595),
           ("Delhi", 28.614, 77.209), ("Hyderabad", 17.385, 78.487)],
    "SG": [("Singapore", 1.352, 103.820)],
    "JP": [("Tokyo", 35.690, 139.692), ("Osaka", 34.694, 135.502)],
    "KR": [("Seoul", 37.567, 126.978)],
    "AE": [("Dubai", 25.205, 55.271), ("Abu Dhabi", 24.453, 54.377)],
    "ZA": [("Johannesburg", -26.204, 28.047), ("Cape Town", -33.925, 18.424)],
    "KE": [("Nairobi", -1.292, 36.822)],
    "NG": [("Lagos", 6.524, 3.379)],
    "BR": [("Sao Paulo", -23.551, -46.633), ("Rio de Janeiro", -22.907, -43.173)],
    "MX": [("Mexico City", 19.433, -99.133)],
}

# HQ locations for the curated real incidents, keyed by the organisation string
# in REAL_INCIDENTS. victim_scope records who the affected people actually were,
# which is usually a much wider set than the HQ country.
#   organisation: (city, lat, lon, victim_scope, data_subject_countries)
REAL_HQ = {
    "Beacon CRM": ("Brighton", 50.822, -0.137, "national", "GB"),
    "Blackbaud": ("Charleston", 32.777, -79.931, "multinational", "US|GB|CA|AU|NL|IE"),
    "Progress Software (MOVEit)": ("Burlington", 42.505, -71.196, "multinational",
                                   "US|GB|CA|DE|CH|IE|AU"),
    "Change Healthcare (UnitedHealth)": ("Nashville", 36.163, -86.781, "national", "US"),
    "British Library": ("London", 51.530, -0.127, "national", "GB"),
    "International Committee of the Red Cross": ("Geneva", 46.204, 6.143, "multinational",
                                                 "CH|KE|NG|ZA|IN"),
    "Synnovis": ("London", 51.503, -0.089, "national", "GB"),
    "Capita": ("London", 51.507, -0.128, "national", "GB|IE"),
    "Advanced (Adastra)": ("Birmingham", 52.489, -1.898, "national", "GB"),
    "SolarWinds": ("Austin", 30.267, -97.743, "multinational", "US|GB|CA|DE|AE"),
    "Kaseya": ("Miami", 25.762, -80.192, "multinational", "US|GB|SE|NL|NZ|ZA"),
    "Colonial Pipeline": ("Alpharetta", 34.075, -84.294, "national", "US"),
    "Equifax": ("Atlanta", 33.749, -84.388, "multinational", "US|GB|CA"),
    "Target": ("Minneapolis", 44.978, -93.265, "national", "US"),
    "A.P. Moller-Maersk": ("Copenhagen", 55.677, 12.569, "multinational",
                           "DK|GB|US|NL|IN|SG"),
    "MGM Resorts International": ("Las Vegas", 36.170, -115.140, "national", "US"),
    "Marks & Spencer": ("London", 51.516, -0.146, "national", "GB|IE"),
    "Snowflake customers (Ticketmaster et al.)": ("Bozeman", 45.680, -111.038,
                                                  "multinational", "US|GB|CA|AU|IN"),
    "23andMe": ("South San Francisco", 37.655, -122.408, "multinational", "US|GB|CA"),
    "Okta": ("San Francisco", 37.775, -122.419, "multinational", "US|GB|DE|AU"),
    "Uber": ("San Francisco", 37.775, -122.419, "multinational", "US|GB|IN|BR|MX"),
    "Optus": ("Sydney", -33.869, 151.209, "national", "AU"),
    "Medibank": ("Melbourne", -37.814, 144.963, "national", "AU"),
    "Rackspace": ("San Antonio", 29.424, -98.494, "multinational", "US|GB"),
    "Scottish Environment Protection Agency": ("Stirling", 56.117, -3.937, "national", "GB"),
    "Redcar & Cleveland Borough Council": ("Redcar", 54.618, -1.070, "national", "GB"),
    "Save the Children Federation": ("Fairfield", 41.141, -73.264, "multinational",
                                     "US|KE|NG"),
}


def country_name(iso2: str) -> str:
    return COUNTRY_META.get(iso2, (iso2,))[0]


def region(iso2: str) -> str:
    m = COUNTRY_META.get(iso2)
    return m[1] if m else "Unknown"


# Plotly choropleths key on ISO-3166-1 alpha-3, not alpha-2. Without this the
# choropleth layer renders completely blank with no error.
ISO2_TO_ISO3 = {
    "GB": "GBR", "IE": "IRL", "US": "USA", "CA": "CAN", "AU": "AUS", "NZ": "NZL",
    "DE": "DEU", "FR": "FRA", "NL": "NLD", "CH": "CHE", "ES": "ESP", "IT": "ITA",
    "SE": "SWE", "NO": "NOR", "DK": "DNK", "PL": "POL", "IN": "IND", "SG": "SGP",
    "JP": "JPN", "KR": "KOR", "AE": "ARE", "ZA": "ZAF", "KE": "KEN", "NG": "NGA",
    "BR": "BRA", "MX": "MEX",
}
