#!/usr/bin/env python3

import argparse
import base64
import glob
import json
import os
import zlib
from datetime import datetime, timezone
from jinja2 import Environment


# --------------------------------------------------
# Builtin names commonly seen in CA policies
# --------------------------------------------------

BUILTIN_NAMES = {
    "All": "All Users",
    "None": "None",
    "GuestsOrExternalUsers": "Guests / External Users",
    "MicrosoftAdminPortals": "Microsoft Admin Portals",
    "Office365": "Office 365",
}

BUILTIN_APPS = {

    # Microsoft first party / common CA targets
    "00000002-0000-0ff1-ce00-000000000000":
        "Exchange Online",

    "00000003-0000-0ff1-ce00-000000000000":
        "Microsoft Graph / SharePoint Online",

    # Microsoft Azure
    "04b07795-8ddb-461a-bbee-02f9e1bf7b46":
        "Microsoft Azure CLI",

    "1950a258-227b-4e31-a9cf-717495945fc2":
        "Microsoft Azure PowerShell",

    "797f4846-ba00-4fd7-ba43-dac1f8f63013":
        "Azure Service Management API",

    "74658136-14ec-4630-ad9b-26e160ff0fc6":
        "Azure Active Directory PowerShell",

    "72f988bf-86f1-41af-91ab-2d7cd011db47":
        "Microsoft Azure Management Portal",

    # Microsoft Admin Portals
    "4ae1bf56-f562-4747-b7bc-2fa3e93e7b0a":
        "Microsoft Admin Portals",

    "c5393580-f805-4401-95e8-94b7a6ef2fc5":
        "Microsoft Portal",

    # Microsoft 365
    "d3590ed6-52b3-4102-aeff-aad2292ab01c":
        "Microsoft Office",

    "00000006-0000-0ff1-ce00-000000000000":
        "Microsoft Office 365 Portal",

    "00000004-0000-0ff1-ce00-000000000000":
        "Microsoft Teams Services",

    # Teams
    "1fec8e78-bce4-4aaf-ab1b-5451cc387264":
        "Microsoft Teams",

    # Intune
    "c1c74fed-04c9-4704-80dc-9f79f5f3d2a7":
        "Microsoft Intune",

    # SharePoint / OneDrive
    "00000005-0000-0ff1-ce00-000000000000":
        "Microsoft 365 Search",

    "ab9b8c07-8f02-4f72-87fa-80105867a763":
        "OneDrive SyncEngine",

    # Exchange REST
    "cc15fd57-2c6c-4117-a88c-83b1d56b0b3b":
        "Microsoft Exchange REST API",

    # Authentication / identity
    "00000002-0000-0000-c000-000000000000":
        "Azure AD Graph",

    "00000001-0000-0000-c000-000000000000":
        "Microsoft Entra ID",

    # MyApps / Access Panel
    "fe930be7-5e62-47db-91af-98c3a49a38bc":
        "Microsoft MyApps",

    # Power Platform
    "9cdead84-a844-4324-93f2-b2e6bb768d07":
        "Power BI Service",

    "a672d62c-fc7b-4e81-a576-e60dc46e951d":
        "Power Apps",

    # Built-in placeholders used by CA
    "All":
        "All cloud apps (Built-in)"

}

# --------------------------------------------------
# Object resolver
# --------------------------------------------------

class Resolver:

    def __init__(self):

        self.users = {}
        self.groups = {}
        self.apps = {}
        self.locations = {}
        self.all_named_locations = []


    # ---------------------------------------------
    # Load Azurehound objects
    # ---------------------------------------------

    def load_file(self, filename):

        try:
            with open(filename, encoding="utf-8") as f:
                data = json.load(f)

        except Exception:
            return


        for item in data.get("data", []):

            kind = item.get("kind")
            obj = item.get("data", {})

            oid = obj.get("id")

            if not oid:
                continue


            record = {

                "id": oid,

                "name":
                    obj.get("userPrincipalName")
                    or obj.get("displayName")
                    or obj.get("appId")
                    or oid,

                "upn":
                    obj.get("userPrincipalName"),

                "display":
                    obj.get("displayName"),

                "appId":
                    obj.get("appId"),

                "kind":
                    kind
            }


            if kind == "AZUser":

                self.users[oid.lower()] = record


            elif kind == "AZGroup":

                self.groups[oid.lower()] = record


            elif kind == "AZServicePrincipal":

                self.apps[oid.lower()] = record

                app_id = obj.get("appId")
                if isinstance(app_id, str) and app_id:
                    self.apps[app_id.lower()] = record



    # ---------------------------------------------
    # Load everything
    # ---------------------------------------------

    def load(self, data_path, policies=None):

        if os.path.isdir(data_path):
            for root, _, files in os.walk(data_path):
                for filename in files:
                    if filename.lower().endswith(".json"):
                        self.load_file(
                            os.path.join(root, filename)
                        )

        elif os.path.isfile(data_path):
            self.load_file(data_path)

        else:
            return


        # Load named locations if policies file provided
        if policies and os.path.exists(policies):
            self.load_locations(policies)



    # ---------------------------------------------
    # Named locations from policies.json
    # policyType == 6
    # ---------------------------------------------

    def load_locations(self, filename):

        try:
            with open(filename, encoding="utf-8") as f:
                data = json.load(f)

        except Exception:
            return


        for item in data.get("value", []):

            if item.get("policyType") != 6:
                continue


            # Index by policyIdentifier, not objectId
            policy_id = item.get("policyIdentifier")

            if not policy_id:
                continue

            display_name = item.get("displayName", policy_id)

            self.locations[policy_id.lower()] = {
                "id": policy_id,
                "name": display_name
            }

            # Parse location details
            location_detail = {
                "id": policy_id,
                "name": display_name,
                "ip_ranges": [],
                "ip_ranges_decompressed": "",
                "categories": [],
                "apply_to_unknown_country": False
            }

            # Extract details from policyDetail entries
            try:
                details = []

                for detail_str in item.get("policyDetail", []):
                    if not isinstance(detail_str, str):
                        continue

                    try:
                        detail = json.loads(detail_str)
                    except Exception:
                        continue

                    if not isinstance(detail, dict):
                        continue

                    details.append(detail)

                for detail in details:
                    if "Categories" in detail and isinstance(detail["Categories"], list):
                        location_detail["categories"].extend(detail["Categories"])

                    if "ApplyToUnknownCountry" in detail:
                        location_detail["apply_to_unknown_country"] = detail.get("ApplyToUnknownCountry", False)

                    if "CountryIsoCodes" in detail and isinstance(detail["CountryIsoCodes"], list):
                        country_codes = [c for c in detail["CountryIsoCodes"] if isinstance(c, str) and c]
                        if country_codes:
                            location_detail["ip_ranges"].append(
                                "Countries: " + ", ".join(country_codes)
                            )

                    if "CidrIpRanges" in detail and isinstance(detail["CidrIpRanges"], list):
                        cidrs = [c for c in detail["CidrIpRanges"] if isinstance(c, str) and c]
                        if cidrs:
                            location_detail["ip_ranges"].append(
                                "IP ranges: " + ", ".join(cidrs)
                            )

                    if "CompressedCidrIpRanges" in detail:
                        compressed = detail["CompressedCidrIpRanges"]
                        decompressed = decompress_cidr_ranges(compressed)
                        if decompressed:
                            location_detail["ip_ranges"].append(decompressed)

                    known_networks = detail.get("KnownNetworkPolicies")
                    if known_networks is not None:
                        if isinstance(known_networks, dict):
                            known_networks = [known_networks]

                        if isinstance(known_networks, list):
                            for network in known_networks:
                                if not isinstance(network, dict):
                                    continue

                                network_name = network.get("NetworkName")
                                cidrs = network.get("CidrIpRanges") or []
                                if isinstance(cidrs, list):
                                    cidrs = [c for c in cidrs if isinstance(c, str) and c]
                                else:
                                    cidrs = []

                                if cidrs:
                                    prefix = f"{network_name}: " if network_name else "Known network: "
                                    location_detail["ip_ranges"].append(prefix + ", ".join(cidrs))

                                categories = network.get("Categories")
                                if isinstance(categories, list):
                                    location_detail["categories"].extend(
                                        [c for c in categories if isinstance(c, str) and c]
                                    )

                                network_countries = network.get("CountryIsoCodes")
                                if isinstance(network_countries, list):
                                    network_countries = [c for c in network_countries if isinstance(c, str) and c]
                                    if network_countries:
                                        location_detail["ip_ranges"].append(
                                            "Countries: " + ", ".join(network_countries)
                                        )

                location_detail["categories"] = sorted(set(location_detail["categories"]))
                location_detail["ip_ranges_decompressed"] = "\n".join(location_detail["ip_ranges"])

            except Exception:
                pass

            self.all_named_locations.append(location_detail)



    # ---------------------------------------------
    # Resolver
    # ---------------------------------------------

    def resolve(self, value, context=None):

        if value is None:
            return "None"


        if not isinstance(value, str):
            return str(value)


        key = value.lower()


        #
        # Context specific builtins
        #

        if value == "All":

            if context == "user":
                return "All users (Built-in)"

            elif context == "application":
                return "All cloud apps (Built-in)"

            elif context == "location":
                return "All locations (Built-in)"

            elif context == "platform":
                return "All platforms (Built-in)"

            else:
                return "All (Built-in)"



        #
        # Named locations
        #

        if context == "location":

            location = self.locations.get(key)

            if location:

                return (
                    location["name"]
                    +
                    " (Named Location)"
                )



        #
        # Users
        #

        user = self.users.get(key)

        if user:

            return (
                user.get("upn")
                or user.get("display")
                or user.get("name")
            ) + " (User)"



        #
        # Groups
        #

        group = self.groups.get(key)

        if group:

            return (
                group.get("display")
                or group.get("name")
            ) + " (Group)"



        #
        # Applications
        #

        if context == "application":

            if key in BUILTIN_APPS:

                return (
                    BUILTIN_APPS[key]
                    +
                    " (Application)"
                )


            app = self.apps.get(key)

            if app:

                return (
                    app.get("display")
                    or app.get("name")
                ) + " (Application)"



        #
        # Generic fallback
        #

        return value


# --------------------------------------------------
# Small helpers
# --------------------------------------------------

def decompress_cidr_ranges(compressed_b64):
    """Decompress base64-encoded deflate-compressed CIDR ranges."""
    try:
        compressed = base64.b64decode(compressed_b64)
        decompressed = zlib.decompress(compressed, -zlib.MAX_WBITS)
        return decompressed.decode('utf-8', errors='ignore')
    except Exception:
        return compressed_b64  # Return original if decompression fails


def extract_values(items, key):

    result = []

    if not isinstance(items, list):
        return result

    for item in items:

        if key in item:
            result.extend(item[key])

    return result


def resolve_list(values, resolver, context=None):

    return [
        resolver.resolve(
            x,
            context
        )
        for x in values
    ]


def pretty_json(obj):

    return json.dumps(
        obj,
        indent=2,
        ensure_ascii=False
    )


# --------------------------------------------------
# Internal policy object
# --------------------------------------------------

class CAPolicy:

    def __init__(self):

        self.name = ""
        self.object_id = ""
        self.state = ""

        self.users_include = []
        self.users_exclude = []

        self.groups_include = []
        self.groups_exclude = []

        self.roles_include = []
        self.roles_exclude = []

        self.guests_or_external_users_include = []
        self.guests_or_external_users_exclude = []

        self.apps_include = []
        self.apps_exclude = []

        self.locations_include = []
        self.locations_exclude = []

        self.platforms = []
        self.platforms_exclude = []
        self.devices_include = []
        self.devices_exclude = []
        self.client_types = []

        self.controls = []
        self.auth_strength_ids = []

        self.sign_in_risks = []
        self.auth_flows = []
        
        self.session_controls = {}

        self.raw = {}


# --------------------------------------------------
# Azure AD Graph Conditional Access parser
# (policyType == 18)
# --------------------------------------------------

def _extract(items, field):
    """Extract values from:
        [
            {"Users":[...]},
            {"Groups":[...]},
            {"Applications":[...]}
        ]
    """
    values = []

    if not isinstance(items, list):
        return values

    for item in items:
        if not isinstance(item, dict):
            continue

        if field in item:
            v = item[field]

            if isinstance(v, list):
                values.extend(v)
            else:
                values.append(v)

    return values


def _extract_conditions(cond, resolver, policy):

    # -----------------------------
    # Users
    # -----------------------------

    users = cond.get("Users", {})

    policy.users_include = resolve_list(
        _extract(users.get("Include", []), "Users"),
        resolver,"user"
    )

    policy.users_exclude = resolve_list(
        _extract(users.get("Exclude", []), "Users"),
        resolver,
    )

    policy.groups_include = resolve_list(
        _extract(users.get("Include", []), "Groups"),
        resolver,
    )

    policy.groups_exclude = resolve_list(
        _extract(users.get("Exclude", []), "Groups"),
        resolver, 
    )

    # -----------------------------
    # Roles
    # -----------------------------

    roles = cond.get("Roles", {})

    policy.roles_include = resolve_list(
        _extract(roles.get("Include", []), "Roles"),
        resolver,
    )

    policy.roles_exclude = resolve_list(
        _extract(roles.get("Exclude", []), "Roles"),
        resolver, 
    )

    # -----------------------------
    # Guests or External Users
    # -----------------------------

    guests = cond.get("GuestsOrExternalUsers", {})

    policy.guests_or_external_users_include = resolve_list(
        _extract(guests.get("Include", []), "GuestsOrExternalUsers"),
        resolver,
    )

    policy.guests_or_external_users_exclude = resolve_list(
        _extract(guests.get("Exclude", []), "GuestsOrExternalUsers"),
        resolver, 
    )

    # -----------------------------
    # Applications
    # -----------------------------

    apps = cond.get("Applications", {})

    policy.apps_include = resolve_list(
        _extract(apps.get("Include", []), "Applications"),
        resolver,
        "application"
    )
    policy.apps_include += _extract(apps.get("Include", []), "ApplicationFilterRule")

    policy.apps_exclude = resolve_list(
        _extract(apps.get("Exclude", []), "Applications"),
        resolver, "application"
    )
    policy.apps_exclude += _extract(apps.get("Exclude", []), "ApplicationFilterRule")

    # -----------------------------
    # Locations
    # -----------------------------

    locations = cond.get("Locations", {})

    policy.locations_include = resolve_list(
        _extract(
            locations.get("Include", []),
            "Locations"
        ),
        resolver,
        "location"
    )


    policy.locations_exclude = resolve_list(
        _extract(
            locations.get("Exclude", []),
            "Locations"
        ),
        resolver,
        "location"
    )

    # -----------------------------
    # Platforms
    # -----------------------------

    platforms = cond.get(
        "DevicePlatforms",
        {}
    )

    policy.platforms = [
        resolver.resolve(
            x,
            "platform"
        )
        for x in _extract(
            platforms.get("Include", []),
            "DevicePlatforms"
        )
    ]


    policy.platforms_exclude = [
        resolver.resolve(
            x,
            "platform"
        )
        for x in _extract(
            platforms.get("Exclude", []),
            "DevicePlatforms"
        )
    ]

    # -----------------------------
    # Devices
    # -----------------------------

    devices = cond.get(
        "Devices",
        {}
    )

    policy.devices_include = resolve_list(
        _extract(devices.get("Include", []), "DeviceRule"),
        resolver,
    )

    policy.devices_exclude = resolve_list(
        _extract(devices.get("Exclude", []), "DeviceRule"),
        resolver,
    )

    # -----------------------------
    # Client Types
    # -----------------------------

    clients = cond.get("ClientTypes", {})

    if isinstance(clients, dict):

        policy.client_types = clients.get(
            "Include",
            []
        )

    elif isinstance(clients, list):

        policy.client_types = clients

    # -----------------------------
    # Sign-In Risks
    # -----------------------------

    risks = cond.get("SignInRisks", {})

    policy.sign_in_risks = _extract(
        risks.get("Include", []),
        "SignInRisks"
    )

    # -----------------------------
    # Auth Flows
    # -----------------------------

    flows = cond.get("AuthFlows", {})

    policy.auth_flows = _extract(
        flows.get("Include", []),
        "AuthFlows"
    )

    # -----------------------------
    # Session Controls
    # -----------------------------

    policy.session_controls = cond.get(
        "SessionControls",
        {}
    )


def _extract_controls(policy_json):

    controls = []

    for c in policy_json.get("Controls", []):

        if not isinstance(c, dict):
            continue

        values = c.get("Control", [])

        if isinstance(values, list):
            controls.extend(values)
        else:
            controls.append(values)

    return controls


def _extract_auth_strength_ids(policy_json):

    auth_strength_ids = []

    for c in policy_json.get("Controls", []):

        if not isinstance(c, dict):
            continue

        values = c.get("AuthStrengthIds", [])

        if isinstance(values, list):
            auth_strength_ids.extend(values)
        else:
            auth_strength_ids.append(values)

    return auth_strength_ids


# --------------------------------------------------
# Parse one policy
# --------------------------------------------------

def parse_policy(raw, resolver):

    # ROADtools only considers policyType 18
    if raw.get("policyType") != 18:
        return None

    if not raw.get("policyDetail"):
        return None

    try:
        detail = json.loads(
            raw["policyDetail"][0]
        )
    except Exception:
        return None

    if "Conditions" not in detail:
        return None

    p = CAPolicy()

    p.name = raw.get(
        "displayName",
        "(Unnamed)"
    )

    p.object_id = raw.get(
        "objectId",
        ""
    )

    p.state = detail.get(
        "State",
        "Unknown"
    )

    p.controls = _extract_controls(detail)
    p.auth_strength_ids = _extract_auth_strength_ids(detail)

    _extract_conditions(
        detail.get("Conditions", {}),
        resolver,
        p,
    )

    p.raw = detail

    return p


# --------------------------------------------------
# Parse all policies
# --------------------------------------------------

def load_policies(filename, resolver):

    with open(filename, encoding="utf-8") as f:
        data = json.load(f)

    policies = []

    for item in data.get("value", []):

        policy = parse_policy(
            item,
            resolver,
        )

        if policy:
            policies.append(policy)

    policies.sort(
        key=lambda x: x.name.lower()
    )

    return policies


# --------------------------------------------------
# Compact helpers for HTML
# --------------------------------------------------

def has_items(values):
    return values is not None and len(values) > 0


def join(values):

    if not values:
        return ""

    return ", ".join(values)


CONTROL_NAMES = {
    "Mfa": "Require MFA",
    "RequireCompliantDevice": "Require compliant device",
    "RequireDomainJoinedDevice": "Require Hybrid Azure AD joined device",
    "RequireApprovedApp": "Require approved client app",
    "RequireCompliantApp": "Require app protection policy",
    "Block": "Block access",
}

STATE_BADGE = {
    "Enabled": "success",
    "Reporting": "warning",
    "Disabled": "secondary",
}


# --------------------------------------------------
# HTML template
# --------------------------------------------------

HTML_TEMPLATE = r"""

<!DOCTYPE html>
<html>

<head>

<meta charset="utf-8">

<title>Conditional Access Report</title>


<style>

body {
    font-family: Segoe UI, Arial, sans-serif;
    background:#f4f6f8;
    margin:20px;
    color:#222;
}

h1 {
    margin-bottom:5px;
}


.subtitle {
    color:#666;
    margin-bottom:15px;
}


.controls {
    background:white;
    padding:12px;
    border-radius:8px;
    margin-bottom:15px;
}


input, select, button {

    padding:8px;
    border-radius:5px;
    border:1px solid #ccc;
    margin-right:5px;

}


.card {

    background:white;
    border-radius:8px;
    padding:15px;
    margin-bottom:15px;

    box-shadow:
    0 2px 5px rgba(0,0,0,.08);

}


.title {

    display:flex;
    justify-content:space-between;
    align-items:center;

}


h2 {

    font-size:18px;
    margin:0;

}


.badge {

    padding:4px 10px;
    border-radius:15px;
    font-size:12px;

}


.success {

    background:#dcfce7;
    color:#166534;

}


.warning {

    background:#fef3c7;
    color:#92400e;

}


.secondary {

    background:#e5e7eb;
    color:#374151;

}


.section {

    margin-top:15px;

}


.section h3 {

    font-size:14px;
    border-bottom:1px solid #ddd;
    padding-bottom:3px;

}


.item {

    margin-left:10px;
    padding:2px;

}


.included {

    color:#166534;

}


.excluded {

    color:#991b1b;

}


.empty {

    color:#888;
    font-style:italic;

}


details {

    margin-top:12px;

}


pre {

    background:#111827;
    color:#d1fae5;
    padding:12px;
    border-radius:6px;
    overflow:auto;
    font-size:12px;

}


table {

    width:100%;
    background:white;
    border-collapse:collapse;
    margin-bottom:15px;

}


td,th {

    padding:8px;
    border-bottom:1px solid #eee;

}

</style>


<script>


function filterPolicies(){

    let q =
    document
    .getElementById("search")
    .value
    .toLowerCase();


    let state =
    document
    .getElementById("stateFilter")
    .value;



    document
    .querySelectorAll(".card")
    .forEach(
        function(card){

            let text =
            card.innerText
            .toLowerCase();


            let textMatch =
            text.includes(q);


            let stateMatch =
            !state ||
            card.dataset.state === state;



            if(
                textMatch &&
                stateMatch
            ){

                card.style.display="block";

            }
            else {

                card.style.display="none";

            }

        }
    );

}



function toggleAll(open){

    document
    .querySelectorAll("details")
    .forEach(
        function(x){

            x.open=open;

        }
    );

}


</script>


</head>


<body>


<h1>
Conditional Access Policies
</h1>


<div class="subtitle">

Generated:
{{generated}}

<br>

Policies:
{{policies|length}}

</div>



<div class="controls">


<input
id="search"
placeholder="Search..."
onkeyup="filterPolicies()"
>


<select
id="stateFilter"
onchange="filterPolicies()"
>

<option value="">
All States
</option>

<option value="Enabled">
Enabled
</option>

<option value="Reporting">
Reporting
</option>

<option value="Disabled">
Disabled
</option>

</select>



<button onclick="toggleAll(true)">
Expand All
</button>


<button onclick="toggleAll(false)">
Collapse All
</button>


</div>




<table>

<tr>
<th>
State
</th>

<th>
Count
</th>

</tr>


{% for state,count in states.items() %}

<tr>

<td>
{{state}}
</td>

<td>
{{count}}
</td>

</tr>

{% endfor %}


</table>




{% for p in policies %}


<div class="card"
data-state="{{p.state}}">


<div class="title">


<h2>
{{p.name}}
</h2>


<span class="badge {{state_badges.get(p.state,'secondary')}}">
{{p.state}}
</span>


</div>


<small>
{{p.object_id}}
</small>




<div class="section">

<h3>
Assignments
</h3>


<b>
Included
</b>


{% if not p.users_include and not p.groups_include and not p.roles_include and not p.guests_or_external_users_include %}

<div class="empty">
None
</div>

{% endif %}



{% for x in p.users_include %}

<div class="item included">
👤 {{x}}
</div>

{% endfor %}



{% for x in p.groups_include %}

<div class="item included">
👥 {{x}}
</div>

{% endfor %}



{% for x in p.roles_include %}

<div class="item included">
🔑 {{x}}
</div>

{% endfor %}



{% for x in p.guests_or_external_users_include %}

<div class="item included">
🌐 {{x}}
</div>

{% endfor %}



<br>


<b>
Excluded
</b>



{% if not p.users_exclude and not p.groups_exclude and not p.roles_exclude and not p.guests_or_external_users_exclude %}

<div class="empty">
None
</div>

{% endif %}



{% for x in p.users_exclude %}

<div class="item excluded">
👤 {{x}}
</div>

{% endfor %}



{% for x in p.groups_exclude %}

<div class="item excluded">
👥 {{x}}
</div>

{% endfor %}



{% for x in p.roles_exclude %}

<div class="item excluded">
🔑 {{x}}
</div>

{% endfor %}



{% for x in p.guests_or_external_users_exclude %}

<div class="item excluded">
🌐 {{x}}
</div>

{% endfor %}


</div>





<div class="section">

<h3>
Applications
</h3>



{% if not p.apps_include and not p.apps_exclude %}

<div class="empty">
None
</div>

{% endif %}



{% for x in p.apps_include %}

<div class="item included">
✓ {{x}}
</div>

{% endfor %}



{% for x in p.apps_exclude %}

<div class="item excluded">
✕ {{x}}
</div>

{% endfor %}


</div>





<div class="section">

<h3>
Devices
</h3>

{% if not p.devices_include and not p.devices_exclude %}
<div class="empty">
None
</div>
{% endif %}

{% for x in p.devices_include %}
<div class="item included">
✓ {{x}}
</div>
{% endfor %}

{% for x in p.devices_exclude %}
<div class="item excluded">
✕ {{x}}
</div>
{% endfor %}


</div>




<div class="section">

<h3>
Controls & Requirements
</h3>


{% if not p.controls and not p.auth_strength_ids %}

<div class="empty">
None
</div>

{% endif %}



{% for c in p.controls %}

<div class="item">
🔐 {{controls.get(c,c)}}
</div>

{% endfor %}


{% for a in p.auth_strength_ids %}

<div class="item">
🔐 Auth Strength: {{a}}
</div>

{% endfor %}


</div>





<div class="section">

<h3>
Other Conditions & Controls
</h3>


{% if p.sign_in_risks %}

<div class="item">

<b>
Sign-In Risks
</b>

{% for x in p.sign_in_risks %}

<br>
🚨 {{x}}

{% endfor %}


</div>

{% endif %}



{% if p.auth_flows %}

<div class="item">

<b>
Auth Flows
</b>

{% for x in p.auth_flows %}

<br>
↔️ {{x}}

{% endfor %}


</div>

{% endif %}



{% if p.platforms or p.platforms_exclude %}

<div class="item">

<b>
Device Platforms
</b>


{% for x in p.platforms %}

<br>
✓ {{x}}

{% endfor %}


{% for x in p.platforms_exclude %}

<br>
✕ {{x}}

{% endfor %}


</div>

{% endif %}



{% if p.client_types %}

<div class="item">
<b>Client Types</b>: {{p.client_types|join(", ")}}
</div>

{% endif %}



{% if p.locations_include or p.locations_exclude %}

<div class="item">
<b>
Locations
</b>

{% for x in p.locations_include %}

<br>
✓ {{x}}

{% endfor %}


{% for x in p.locations_exclude %}

<br>
✕ {{x}}

{% endfor %}
</div>

{% endif %}



{% if p.session_controls %}

<div class="item">

<b>
Session Controls
</b>

{% for name, value in p.session_controls.items() %}

<br>
⏱️ {{name}}: {{value|tojson}}

{% endfor %}


</div>

{% endif %}



</div>





<details>

<summary>
Raw JSON
</summary>


<pre>
{{p.raw | pretty}}
</pre>


</details>



</div>


{% endfor %}




{% if named_locations %}

<hr style="margin-top:40px; margin-bottom:30px;">

<h2>
Named Locations
</h2>

<table>

<tr>
<th>
Location Name
</th>

<th>
Categories
</th>

<th>
IP Ranges / Countries
</th>

</tr>


{% for loc in named_locations %}

<tr>

<td>
<strong>{{loc.name}}</strong>
</td>

<td>
{% if loc.categories %}
{{loc.categories|join(", ")}}
{% else %}
<em>None</em>
{% endif %}
</td>

<td>
{% if loc.ip_ranges_decompressed %}
<code style="font-size:12px; word-break:break-all; white-space:pre-wrap;">{{loc.ip_ranges_decompressed}}</code>
{% else %}
<em>N/A</em>
{% endif %}
</td>

</tr>

{% endfor %}


</table>

{% endif %}



</body>

</html>

"""

# --------------------------------------------------
# HTML rendering
# --------------------------------------------------

def render_report(
        policies,
        resolver,
        output
):

    states = {}

    for p in policies:

        states[p.state] = (
            states.get(
                p.state,
                0
            ) + 1
        )


    env = Environment()

    env.filters["pretty"] = pretty_json

    template = env.from_string(
        HTML_TEMPLATE
    )


    html = template.render(

        policies=policies,

        generated=datetime.now(
            timezone.utc
        ).strftime(
            "%Y-%m-%d %H:%M UTC"
        ),

        states=states,

        controls=CONTROL_NAMES,

        state_badges=STATE_BADGE,

        named_locations=resolver.all_named_locations,

    )


    with open(
        output,
        "w",
        encoding="utf-8"
    ) as f:

        f.write(html)



    print(
        f"[+] Written {output}"
    )



# --------------------------------------------------
# Main
# --------------------------------------------------

def main():


    parser = argparse.ArgumentParser(
        description=
        "ROADrecon style Azure AD Conditional Access HTML report"
    )


    parser.add_argument(
        "-p",
        "--policies",
        required=True,
        help="Azure policy JSON export"
    )


    parser.add_argument(
        "-d",
        "--data",
        required=True,
        help="JSON file or folder containing Azurehound data"
    )


    parser.add_argument(
        "-o",
        "--output",
        default="conditional_access.html"
    )


    args = parser.parse_args()



    print(
        "[*] Loading Azure objects..."
    )


    resolver = Resolver()

    resolver.load(
        args.data,
        args.policies
    )


    print(
        f"    Users: {len(resolver.users)}"
    )

    print(
        f"    Groups: {len(resolver.groups)}"
    )

    print(
        f"    Apps: {len(resolver.apps)}"
    )

    print(
        f"    Locations: {len(resolver.locations)}"
    )



    print(
        "[*] Parsing Conditional Access policies..."
    )


    policies = load_policies(
        args.policies,
        resolver
    )


    print(
        f"    Parsed {len(policies)} policies"
    )



    render_report(
        policies,
        resolver,
        args.output
    )



if __name__ == "__main__":

    main()