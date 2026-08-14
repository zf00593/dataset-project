"""
incident_analysis.py
====================

Methods tagged [REAL-ONLY] use only the curated public incidents, and are the
ones safe to quote to an audience — with the source column cited.
"""

from __future__ import annotations

import numpy as np
import pandas as pd
from scipy import stats

# Human vectors for attacks
HUMAN_FACTOR_VECTORS = {
    "Phishing",
    "Compromised credentials",
    "Credential stuffing",
    "MFA fatigue",
    "Help-desk social engineering",
    "Negligent insider",
    "Third-party supplier access",
}

# Technical vectors for attacks
TECHNICAL_VECTORS = {
    "Unpatched vulnerability",
    "Zero-day exploit",
    "Insecure API endpoint",
    "Misconfigured cloud storage",
    "Exposed RDP/VPN",
    "Trojanised software update",
    "Malicious dependency",
    "Volumetric flood",
    "Application-layer flood",
    "Malicious insider",
}

# Detection routes where somebody outside the organisation had to tell them.
EXTERNAL_DETECTION = {
    "Third-party notification",
    "Law enforcement notification",
    "Customer report",
    "Public leak / dark web",
}

SEVERITY_ORDER = ["low", "medium", "high", "critical"]


class IncidentAnalysis:
    """Analysis of a cyber-incident dataset."""

    def __init__(self, path: str = "cyber_incidents.csv"):
        # Reads the csv
        df = pd.read_csv(path)

        ### Type converstion ###
        # Converts the column to datetime data type from string
        for col in ("date_occurred", "date_discovered", "date_disclosed"):
            df[col] = pd.to_datetime(df[col], errors="coerce")

        # Converts the columns to integer data type from string
        for col in ("records_affected", "downstream_orgs_affected", "dwell_time_days",
                    "ransom_demanded_usd", "downtime_days", "estimated_cost_usd"):
            df[col] = pd.to_numeric(df[col], errors="coerce")
       

        # Selects the columns, converts the value to string, makes them lowercase and then returns boolean by comparing if the string is "true"
        df["is_synthetic"] = df["is_synthetic"].astype(str).str.lower() == "true"
        df["supply_chain"] = df["supply_chain"].astype(str).str.lower() == "true"
         ### END of type converstion ###

        ### Deriving new columns ###
        
        # Derives new column for date by using the datetime accessor and extract the year
        df["year"] = df["date_discovered"].dt.year
        
        # Converts the date into quarterly periods and then a string
        df["quarter"] = df["date_discovered"].dt.to_period("Q").astype(str)
        
        # Derives a new column for the time it took to disclose after discovery and turns it into a number of days
        df["disclosure_lag_days"] = (
            df["date_disclosed"] - df["date_discovered"]
        ).dt.days

        # Classifies the attack vector into human factor, technical or other. Uses substring matching for unclassified vectors.
        # NP select works like multiple if elif else statements
        df["vector_class"] = np.select(
            [df["attack_vector"].isin(HUMAN_FACTOR_VECTORS), # first condition
             df["attack_vector"].isin(TECHNICAL_VECTORS)], # second condition
            ["Human factor", "Technical"], # choices
            default="Other", # default value
        )
        

        # Finds rows that are neith human factor or technical
        unclassified = df["vector_class"] == "Other"
        
        # Unclassified is a boolean column for vector_class as "Other", then it uses substring matching to see if the string contains any of the following in attack vector, it then makes it 
        df.loc[unclassified, "vector_class"] = np.where(
            df.loc[unclassified, "attack_vector"].str.contains(
                "credential|phish|social engineering|supplier|MFA", case=False, na=False
            ),
            "Human factor", # if substring is found
            "Technical", # if substring isn't found
        )

        # Makes a column that checks if it was found in house or externally
        df["detection_class"] = np.where(
            df["detection_method"].isin(EXTERNAL_DETECTION),
            "Found by someone else",
            "Found in-house",
        )
        # Takes lgo base 10 on the number of records affected if greater than 0 (can't log 0)
        df["log10_records"] = np.log10(df["records_affected"].where(df["records_affected"] > 0))
        
        # Makes the severity column a categorical variable with an order of low, medium, high, critical
        df["severity"] = pd.Categorical(df["severity"], SEVERITY_ORDER, ordered=True)
        
        # Makes a boolean column for whether sensitive data was exposed based on the data types exposed column
        df["sensitive_data"] = df["data_types_exposed"].str.contains(
            "health|safeguarding|ssn_or_ni_number|bank_details|credit_card", na=False
        )
        ### END of derived columns ###

        ### ATTRIBUTES ###
        self.df = df
        ### END of attributes ###

    # ------------------------------------------------------------------ #
    # Headline framing
    # ------------------------------------------------------------------ #

    def headline_stats(self):
        """Returns the small set of numbers worth putting on an opening slide.

        Returns:
            pd.Series: Named headline figures across the full dataset.
        """
        d = self.df
        return pd.Series({
            "incidents_total": len(d),
            # Percentage of incidents whose initial access was a human-factor vector. It calculates using mean the proportion and then rounds it to 1 decimal place
            "pct_human_factor_entry": round(
                (d["vector_class"] == "Human factor").mean() * 100, 1),
            
            # percentage of incidents found by someone else
            "pct_found_by_someone_else": round(
                (d["detection_class"] == "Found by someone else").mean() * 100, 1),
            
            # median dwell time in days across all incidents
            "median_dwell_days": d["dwell_time_days"].median(),
            
            # Finds median dwell time for incidents that were found by someone else
            # loc takes a condition and then selects the dwell_time_days column and then takes the median
            "median_dwell_days_external_detection": d.loc[
                d["detection_class"] == "Found by someone else", "dwell_time_days"].median(),
            
            # Finds the percentage of supply chain incidents
            "pct_supply_chain": round(d["supply_chain"].mean() * 100, 1),
            
            # Finds the percentage of incidents that exposed sensitive data
            "pct_exposing_sensitive_data": round(d["sensitive_data"].mean() * 100, 1),
            
            # Finds the sum of all records affected across all incidents
            "people_affected__incidents": int(self.df["records_affected"].sum()),
        })

    def awareness_preventable_share(self):
        """Share of incidents whose initial access was a human-factor vector.

        The single most persuasive chart in the set: it shows that the entry
        point is usually a person, not an exotic exploit.

        Returns:
            pd.DataFrame: Counts and percentages by vector_class, split real vs synthetic.
        """
        
        # counts how many times each vector class appears and then converts the count to dataframe called total
        counts = self.df["vector_class"].value_counts().to_frame("total")
        # For each vector class it finds the proportion that it was that vector class
        counts["pct_of_all"] = (counts["total"] / counts["total"].sum() * 100).round(1)

        # Returns sorted by total in descending order
        return counts.sort_values("total", ascending=False)

    def top_vectors(self, n: int = 10):
        """Most common initial-access vectors, with their human/technical class.

        Args:
            n (int): Number of vectors to return.

        Returns:
            pd.DataFrame: Vector, count, percentage and class, descending by count.
        """
        # Splits the data frame into groups based on the values in the specified column to have all unique permuatations in dataaset
        # Then it counts how many records belong to each group
        # Then it converts the grouped result into a data frame with a new column called count
        # It then sorts the rows descending based on count and returns the first n
        out = (
            self.df.groupby(["attack_vector", "vector_class"], observed=True)
            .size().reset_index(name="count")
            .sort_values("count", ascending=False).head(n)
        )
        
        # Then it adds a new column for percentages 
        out["pct"] = (out["count"] / len(self.df) * 100).round(1)
        # Adds a new index now for the successive rows
        return out.reset_index(drop=True)

    # ------------------------------------------------------------------ #
    # Detection and dwell time — the "you won't notice" argument
    # ------------------------------------------------------------------ #

    def dwell_time_by_incident_type(self):
        """Dwell-time distribution (intrusion to discovery) by incident type.

        Returns:
            pd.DataFrame: Count, median, IQR and max dwell days per incident type.
        """
        # Groups the data frame by incident type and then selects the dwell time days values fopr each group
        g = self.df.groupby("incident_type", observed=True)["dwell_time_days"]
        # Creates a new data frame with the count, median, 25th percentile, 75th percentile and max dwell time days for each incident type  
        out = pd.DataFrame({
            "count": g.size(),
            "median_days": g.median(),
            "q25": g.quantile(0.25),
            "q75": g.quantile(0.75),
            "max_days": g.max(),
        })
        # Sorts the incident types by median dwell time days
        return out.sort_values("median_days", ascending=False)

    def dwell_time_by_detection(self):
        """Dwell time split by whether the org found it or was told about it.

        The gap here is the case for monitoring and for staff reporting quickly:
        organisations that rely on an outside party to notice sit exposed longer.

        Returns:
            pd.DataFrame: Count, median and mean dwell days per detection method.
        """
        
        # Groups by the detection class (in-house or found by someone else) and method (e.g. law enforcement)
        # Selects dwell time days
        g = self.df.groupby(["detection_class", "detection_method"], observed=True)["dwell_time_days"]
       
        # Creates a new data frame with the count, median and mean dwell time days for each detection class and method
        # Sorts descending by median dwell time dayas
        return pd.DataFrame({
            "count": g.size(),
            "median_days": g.median(),
            "mean_days": g.mean().round(1),
        }).sort_values("median_days", ascending=False)

    def dwell_gap_significance(self):
        """Tests whether externally-detected incidents sit undiscovered longer.

        Mann-Whitney U on synthetic rows only (n is adequate); the real rows are
        too few to test and are excluded.

        Returns:
            pd.Series: Group medians, U statistic, p-value and rank-biserial effect size.
        """
        # Selects dwell time days for all incidents found by someone else
        a = self.df.loc[self.df["detection_class"] == "Found by someone else",
                         "dwell_time_days"].dropna()
        # Selects dwell time days for all incidents found in house
        b = self.df.loc[self.df["detection_class"] == "Found in-house",
                         "dwell_time_days"].dropna()
        
        # Seses if the dwell time days have different distributions
        # u statistic represents how the rankings differ
        # p tells us if it is significant
        u, p = stats.mannwhitneyu(a, b, alternative="two-sided")
        return pd.Series({
            "n_external": len(a),
            "n_internal": len(b),
            "median_external": a.median(),
            "median_internal": b.median(),
            "u_statistic": u,
            "p_value": p,
            "rank_biserial": round(1 - (2 * u) / (len(a) * len(b)), 3),
        })

    def disclosure_lag_by_regulator(self):
        """Days from discovery to disclosure, split by whether a regulator was notified.

        Returns:
            pd.DataFrame: Count, median and 90th-percentile disclosure lag per group.
        """
        # Groups the data frame by whether the regulator was notified and then selects the disclosure lag days values for each group
        g = self.df.groupby("regulator_notified", observed=True)["disclosure_lag_days"]
        # Checks the disclosure lag days for each group and returns a new data frame with the count, median and 90th percentile disclosure lag days for each group
        return pd.DataFrame({
            "count": g.size(),
            "median_days": g.median(),
            "p90_days": g.quantile(0.90),
        })

    # ------------------------------------------------------------------ #
    # Who gets hit, and how hard
    # ------------------------------------------------------------------ #

    def sector_impact_profile(self):
        """Per-sector incident count, typical scale and sensitive-data exposure.

        Returns:
            pd.DataFrame: One row per sector, sorted by median records affected.
        """
        # Groups by the different sectors
        g = self.df.groupby("sector", observed=True)
        
        # Finds the number of incidents, the median number affected and median dwell time days for each sector
        # Finds the percentage of supply chain attacks, sensitive data leak and human factor for each sector
        out = pd.DataFrame({
            "incidents": g.size(),
            "median_records": g["records_affected"].median(),
            "median_dwell_days": g["dwell_time_days"].median(),
            "pct_supply_chain": (g["supply_chain"].mean() * 100).round(1),
            "pct_sensitive_data": (g["sensitive_data"].mean() * 100).round(1),
            "pct_human_factor": (g["vector_class"]
                                 .apply(lambda s: (s == "Human factor").mean() * 100).round(1)),
        })
        # Sorts by median number of records affected in eachs sector
        return out.sort_values("median_records", ascending=False)


    def vector_by_sector(self, normalise: bool = True):
        """Cross table of initial-access vector class against sector.

        Args:
            normalise (bool): If True, return column percentages instead of counts.

        Returns:
            pd.DataFrame: Sector by vector_class cross table.
        """
        # Creates a cross table between the vector class and the sector
        ct = pd.crosstab(self.df["vector_class"], self.df["sector"])
        # If normalise (parameter) is true it returns a table of percentages 
        return (ct / ct.sum() * 100).round(1) if normalise else ct

    def charity_vs_rest(self):
        """Compares nonprofit organisations against everyone else.

        Nonprofits hold donor, beneficiary and safeguarding data on smaller
        budgets. This method shows the resulting asymmetry — comparable exposure
        of sensitive data, lower spend on response.

        Returns:
            pd.DataFrame: Side-by-side metrics for nonprofit vs other org types.
        """
        # Creates a copy of the data frame
        d = self.df.copy()
        # Adds a new group column that checks if the org type is nonprofit or not
        d["group"] = np.where(d["org_type"] == "nonprofit", "Nonprofit", "Other")
        # Groups incident records by groups
        g = d.groupby("group", observed=True)
        
        # Returns a data frame with number of incidents in each group, median number of records affected, median estimated cost in USD, cost per record in USD, percentage of incidents that exposed sensitive data, percentage of incidents that were human factor and median dwell time days
        return pd.DataFrame({
            "incidents": g.size(),
            "median_records": g["records_affected"].median(),
            "median_cost_usd": g["estimated_cost_usd"].median(),
            "cost_per_record_usd": (g["estimated_cost_usd"].median()
                                    / g["records_affected"].median()).round(2),
            "pct_sensitive_data": (g["sensitive_data"].mean() * 100).round(1),
            "pct_human_factor": g["vector_class"].apply(
                lambda s: round((s == "Human factor").mean() * 100, 1)),
            "median_dwell_days": g["dwell_time_days"].median(),
        }).T

    # ------------------------------------------------------------------ #
    # Supply chain — the Beacon CRM argument
    # ------------------------------------------------------------------ #

    def supply_chain_blast_radius(self):
        """Compares scale of supply-chain incidents against direct ones.

        One compromised vendor reaches every customer at once. This is the
        quantitative version of "your CRM provider's security posture is yours".

        Returns:
            pd.DataFrame: Scale metrics split by whether a third party was involved.
        """
        
        # Groups incidents by whether supply chain or not
        g = self.df.groupby("supply_chain", observed=True)
        
        # shows number of incidents, median of records affected, 90th percentile of records affected, median dwell time days and median downstream orgs affected for each group
        out = pd.DataFrame({
            "incidents": g.size(),
            "median_records": g["records_affected"].median(),
            "p90_records": g["records_affected"].quantile(0.90),
            "median_dwell_days": g["dwell_time_days"].median(),
            "median_downstream_orgs": g["downstream_orgs_affected"].median(),
        })
        # Maps the index to a new value of "Via third party" if True and "Direct" if False
        out.index = out.index.map({True: "Via third party", False: "Direct"})
        
        # Calculates the ratio of median records affected for each group against the median records affected for direct incidents and rounds it to 2 decimal places
        # Ratio tells you how many more records are affected in supply chain incidents compared to direct incidents
        out["records_multiplier_vs_direct"] = (
            out["median_records"] / out.loc["Direct", "median_records"]).round(2)
        return out

    def downstream_reach(self):
        """ Real supply-chain incidents ranked by downstream organisations hit.

        Use these as annotated points over the synthetic distribution — they are
        the anchors that make the synthetic spread credible.

        Returns:
            pd.DataFrame: Real supply-chain incidents with reach, records and source.
        """
        # Columns to keep in final output
        cols = [
            "incident_name",
            "organisation",
            "sector",
            "date_discovered",
            "downstream_orgs_affected",
            "records_affected",
            "attack_vector",
            "source"
        ]

        # Filter self.df to rows where supply chian is true the orders them by the number of downstream orgs affected@
        # Then sorts
        return (
            self.df[self.df["supply_chain"]][cols]
            .sort_values("downstream_orgs_affected", ascending=False)
            .reset_index(drop=True)
        )

    def credential_led_incidents(self):
        """Real incidents whose entry point was credentials or social engineering.

        The list an audience should see immediately after being told that most
        breaches start with a person: recognisable names, mundane causes.

        Returns:
            pd.DataFrame: Real human-factor incidents with scale and source.
        """
        # gets columns
        cols = [
            "incident_name",
            "organisation",
            "sector",
            "date_discovered",
            "attack_vector",
            "records_affected",
            "estimated_cost_usd",
            "source"
        ]

        # Finds all records where the vector is human factor
        # Sorts by the date discovered and resets index
        return (
            self.df[self.df["vector_class"] == "Human factor"][cols]
            .sort_values("date_discovered", ascending=False)
            .reset_index(drop=True)
        )

    # ------------------------------------------------------------------ #
    # Trends and correlation
    # ------------------------------------------------------------------ #

    def incidents_over_time(self, freq: str = "quarter"):
        """Incident counts over time by incident type.

        Note: synthetic incident dates are drawn uniformly across the configured
        window, so any apparent trend in the synthetic rows is sampling noise.
        Plot it for shape, not for direction.

        Args:
            freq (str): "quarter" or "year".

        Returns:
            pd.DataFrame: Period by incident_type counts.
        """
        # Creates a new column called quarter if freq is quarter and year if freq is year
        key = "quarter" if freq == "quarter" else "year"
        # Returns a cross table of the incident_type by the frequency showing the number of incidents for each year and incident type
        return pd.crosstab(self.df[key], self.df["incident_type"])

    def correlation_matrix(self, method: str = "spearman", drop_derived: bool = True):
        """Rank correlation between the numeric impact measures.

        Args:
            method (str): "spearman" (default, robust to the heavy tails) or "pearson".
            drop_derived (bool): If True, excludes estimated_cost_usd, which the
                generator computes from records and downtime — leaving it in
                manufactures a correlation you already know the answer to.

        Returns:
            pd.DataFrame: Correlation matrix of numeric impact columns.
        """
        # Gets the columns needed
        cols = ["records_affected", "dwell_time_days", "downtime_days",
                "downstream_orgs_affected", "disclosure_lag_days", "ransom_demanded_usd"]

        # Optiionally adds estimated cost
        if not drop_derived:
            cols.append("estimated_cost_usd")
        # calculates the correlation between all the pairs of selected columns
        return self.df[cols].corr(method=method).round(3)

    def severity_by_vector_class(self):
        """[CIRCULAR] Severity distribution across human-factor vs technical entry.

        `severity` is computed by the generator from records, downtime, supply
        chain and data sensitivity. This cross table is therefore a restatement
        of that rule, not an independent result. Fine as a legend for the
        severity scale; not evidence.

        Returns:
            pd.DataFrame: Row-normalised percentages of severity per vector class.
        """
        # Does a cross table between the attack vectors and severities into percentages
        ct = pd.crosstab(self.df["vector_class"], self.df["severity"],
                         normalize="index") * 100
        return ct.round(1)

    def ransom_outcomes(self):
        """Cross table of ransom payment decision against incident severity.

        Returns:
            pd.DataFrame: ransom_paid by severity counts, ransomware rows only.
        """
        # Filters the data frame to only include rows with ransomware and destructive malware
        r = self.df[self.df["incident_type"].isin(["Ransomware", "Destructive malware"])]
        # Returns a crosstable between ransom payment and severity
        return pd.crosstab(r["ransom_paid"], r["severity"])

    def missingness_profile(self):
        """Percentage of missing values per column, split real vs synthetic.

        Worth showing an audience: incident reporting is patchy, and absence of
        a number is not absence of harm.

        Returns:
            pd.DataFrame: Percent missing per column for each subset.
        """
        # Finds the percentage of values missing in each column and returns a data frame with the percentage of missing values for each column sorted in descending order
        return pd.DataFrame({
            "pct_missing": (self.df.isna().mean() * 100).round(1),
        }).sort_values("pct_missing", ascending=False)


    # ------------------------------------------------------------------ #
    # Timelines
    # ------------------------------------------------------------------ #

    def lifecycle_timeline(self, subset: str = "real", top_n: int = 20,
                           sort_by: str = "date_occurred"):
        """Per-incident lifecycle bars: intrusion, discovery, disclosure.

        Shaped for a Gantt/broken_barh chart. Each row gives two spans measured
        in days from the incident's own start: the exposure window (attacker in,
        nobody knows) and the notification window (org knows, victims do not).

        Args:
            subset (str): "real", "synthetic" or "all".
            top_n (int): Maximum rows returned.
            sort_by (str): Column to sort on, e.g. "date_occurred" or "exposure_days".

        Returns:
            pd.DataFrame: Label, absolute dates, and span lengths for plotting.
        """
        
        # Copies the following columns from the table
        out = self.df[[
            "incident_id", "incident_name", "organisation", "sector",
            "date_occurred", "date_discovered", "date_disclosed",
            "records_affected", "severity"
        ]].copy()

        # Exposure days is the difference between the date discovered and the date occurred
        out["exposure_days"] = (
            out["date_discovered"] - out["date_occurred"]
        ).dt.days


        out["notification_days"] = (
            out["date_disclosed"] - out["date_discovered"]
        ).dt.days

        # Total days is the sum of the days the data was exposed and the days it took to notify
        out["total_days"] = out["exposure_days"] + out["notification_days"]

        # Creates a new column called label that is the first 38 characters of the organisation name
        out["label"] = out["organisation"].str.slice(0, 38)

        # Creates a boolean variabe that is true or false depending on if sort by starts with date
        ascending = sort_by.startswith("date")

        # SOrts the data frame by the sort by column in ascending or descending order depending on the sort_by attribute
        # takes the top n rows
        # resets the index
        return (
            out.sort_values(sort_by, ascending=ascending)
            .head(top_n)
            .reset_index(drop=True)
        )

    def exposure_window_ranking(self, subset: str = "all", top_n: int = 15):
        """Incidents ranked by how long the attacker went unnoticed.

        The blunt version of the awareness message: a horizontal bar chart where
        the bars are measured in months, not hours.

        Args:
            subset (str): "real", "synthetic" or "all".
            top_n (int): Number of incidents to return.

        Returns:
            pd.DataFrame: Longest exposure windows with scale and detection route.
        """
        # Names of columns
        cols = [
            "incident_name",
            "organisation",
            "sector",
            "dwell_time_days",
            "detection_method",
            "records_affected"
        ]

        #  Sorts by the dwell time, takes the top n rows and copies the data frame 
        out = (
            self.df[cols]
            .sort_values("dwell_time_days", ascending=False)
            .head(top_n)
            .copy()
        )

        # Creates a new column called dwell months which is the dwell days divided by average month length
        out["dwell_months"] = (out["dwell_time_days"] / 30.44).round(1)

        # Returns the incidents sorted by dwell days (exposure)
        return out.reset_index(drop=True)

    def response_lag_decomposition(self, subset: str = "real", top_n: int = 20):
        """Splits total time-to-public into exposure and notification phases.

        Plots as a stacked horizontal bar. The second segment is the one an
        audience reacts to: the days an organisation knew and they did not.

        Args:
            subset (str): "real", "synthetic" or "all".
            top_n (int): Number of incidents to return.

        Returns:
            pd.DataFrame: Two-segment breakdown per incident, longest total first.
        """
        
        # Calls the lifecycle_timeline method to get the exposure and notification days for each incident
        t = self.lifecycle_timeline(subset=subset, top_n=10**6)
        
        # Selects the columns needed for the output data frame
        out = t[["label", "sector", "exposure_days", "notification_days", "total_days"]]
        
        # Sorts the data frame by total days in descending order, takes the top n rows and resets the index
        return out.sort_values("total_days", ascending=False).head(top_n).reset_index(drop=True)

    def incident_volume_timeline(self, freq: str = "Q", by: str = "incident_type",
                                 cumulative: bool = False):
        """Incident counts over time, optionally cumulative, split by a category.

        Args:
            freq (str): Pandas offset alias, e.g. "M", "Q", "Y".
            by (str): Column to split series on, e.g. "incident_type", "sector",
                "vector_class", "severity".
            cumulative (bool): If True, return a running total.

        Returns:
            pd.DataFrame: Period index by category counts.
        """
        # Drops rows with missing date_discovered values
        d = self.df.dropna(subset=["date_discovered"])
        
        # Converts the date_discovered column to a period with the specified frequency
        periods = d["date_discovered"].dt.to_period(freq)
        
        # Creates a cross table of frequency by the specified category and the periods
        ct = pd.crosstab(periods, d[by])
        # Converts the index of the cross table to string
        ct.index = ct.index.astype(str)
        
        # If cumulative is true it returns the cumulative sum (as it goes down it sums) of the cross table otherwise it returns the cross table
        return ct.cumsum() if cumulative else ct
1
    def cumulative_records_timeline(self, subset: str = "real", freq: str = "Y"):
        """Running total of people whose data was exposed, over time.

        A step chart of this is the most affecting single visual available from
        this dataset, because the y-axis is people rather than incidents.

        Args:
            subset (str): "real", "synthetic" or "all".
            freq (str): Pandas offset alias, e.g. "Q" or "Y".

        Returns:
            pd.DataFrame: Period, records in period, and cumulative total.
        """
        # Drops rows with missing date_disclosed or records_affected values
        d = self.df.dropna(subset=["date_disclosed", "records_affected"])

        # Converts date disclosed into period of frequency and then groups by those buckets
        g = d.groupby(d["date_disclosed"].dt.to_period(freq), observed=True)

        # Creates a data frame with the number of incidents and the sum of records affected for each period
        out = pd.DataFrame({
            "incidents": g.size(),
            "records_in_period": g["records_affected"].sum(),
        })

        # Creates a new column called cumulative records which is the cumulative sum of the records in period column
        out["cumulative_records"] = out["records_in_period"].cumsum()

        out.index = out.index.astype(str)

        return out


    def dwell_trend_by_year(self, by: str = "vector_class"):
        """Median dwell time per year, split by a category.

        Args:
            by (str): Column to split on, e.g. "vector_class" or "incident_type".

        Returns:
            pd.DataFrame: Year by category median dwell days.
        """
        d = self.df.dropna(subset=["year"])
        return (d.pivot_table(index="year", columns=by, values="dwell_time_days",
                              aggfunc="median", observed=True).round(1))

    def sector_period_heatmap(self, freq: str = "Y"):
        """Incident counts by sector and period, for a heatmap.

        Args:
            freq (str): Pandas offset alias, e.g. "Q" or "Y".

        Returns:
            pd.DataFrame: Sector rows by period columns.
        """
        d = self.df.dropna(subset=["date_discovered"])
        periods = d["date_discovered"].dt.to_period(freq).astype(str)
        return pd.crosstab(d["sector"], periods)

    def beacon_event_timeline(self):
        """[REAL-ONLY] Day-by-day milestones of the Beacon CRM charity breach.

        A single annotated timeline of one incident lands harder with a charity
        audience than any aggregate. Note the five-day gap between the vendor
        knowing and customers being told, and the further two days before the
        sector press picked it up.

        Dates from Beacon CRM customer notifications, SCVO guidance, and
        reporting by The Register and BankInfoSecurity, August 2026. Verify
        against those sources before presenting; the investigation was ongoing
        at time of writing and figures were provisional.

        Returns:
            pd.DataFrame: Dated milestones with actor, day offset and phase.
        """
        events = [
            ("2026-07-27", "Latest data known to be in the copied backups",
             "Attacker", "Exposure"),
            ("2026-07-29", "Beacon becomes aware of unauthorised access; external "
             "specialists engaged", "Vendor", "Exposure"),
            ("2026-08-03", "Beacon notifies customers; told to assume all stored data "
             "downloaded", "Vendor", "Notification"),
            ("2026-08-03", "Charities begin notifying supporters (Molly Rose Foundation, "
             "English National Ballet, Upper Room)", "Charities", "Notification"),
            ("2026-08-04", "SCVO issues guidance to Scottish charities", "Sector body",
             "Response"),
            ("2026-08-05", "Reported in the security and sector press", "Press", "Response"),
            ("2026-08-05", "ICO confirms it has received reports from affected "
             "organisations", "Regulator", "Response"),
        ]
        out = pd.DataFrame(events, columns=["date", "event", "actor", "phase"])
        out["date"] = pd.to_datetime(out["date"])
        out["day_offset"] = (out["date"] - out["date"].min()).dt.days
        return out

    def milestone_timeline(self, incident_id: str):
        """Long-format milestone rows for any single incident, for an annotated timeline.

        Args:
            incident_id (str): Value from the incident_id column, e.g. "REAL-0001".

        Returns:
            pd.DataFrame: One row per dated milestone, with days from first event.
        """
        row = self.df[self.df["incident_id"] == incident_id]
        if row.empty:
            raise KeyError(f"No incident with id {incident_id!r}")
        row = row.iloc[0]
        out = pd.DataFrame({
            "milestone": ["Intrusion begins", "Discovered", "Disclosed"],
            "date": [row["date_occurred"], row["date_discovered"], row["date_disclosed"]],
        }).dropna(subset=["date"])
        out["day_offset"] = (out["date"] - out["date"].min()).dt.days
        out["incident_name"] = row["incident_name"]
        out["organisation"] = row["organisation"]
        return out
    
    
        
      


if __name__ == "__main__":
    pd.set_option("display.width", 140)
    a = IncidentAnalysis("extracted_files/cyber_incidents.csv")
    for name in ("headline_stats", "awareness_preventable_share", "dwell_time_by_detection",
                 "dwell_gap_significance", "supply_chain_blast_radius", "charity_vs_rest",
                 "correlation_matrix",
                 "beacon_event_timeline", "response_lag_decomposition",
                 "cumulative_records_timeline", "exposure_window_ranking"):
        print(f"\n=== {name} ===")
        print(getattr(a, name)())
