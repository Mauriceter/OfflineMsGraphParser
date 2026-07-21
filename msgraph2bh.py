#!/usr/bin/env python3
"""
Microsoft Graph -> BloodHound (Azure) JSON converter.

The output format and every field mapping below were reverse-engineered from
the reference files in ``bh/`` and cross-checked against the AzureHound source
(https://github.com/SpecterOps/AzureHound), which produced them.

Output shape::

    {
        "data": [ {"kind": "AZUser", "data": { ... }}, ... ],
        "meta": {"type": "azure", "version": 5, "count": <len(data)>}
    }

Key rules learned from AzureHound's Go models:

  * Each node embeds a DirectoryObject/Entity whose ``id`` (no ``omitempty``)
    is serialised first, followed by the struct fields in declaration order.
    We therefore emit ``id`` first and keep the exact per-type field order.
  * Scalar/slice fields use Go ``omitempty``: null, "", false, 0 and [] are
    dropped.  Object-typed struct fields are NEVER dropped by ``omitempty`` and
    are always emitted (as ``{}`` when empty) - e.g. a user's
    ``employeeOrgData`` / ``mailboxSettings`` / ``onPremisesExtensionAttributes``
    / ``passwordProfile`` or an application's ``api`` / ``web`` / ...
  * Users are collected with a fixed ``$select``; groups/devices/apps/roles are
    not, so they expose their full struct field set.

This script consumes raw Graph responses (as saved from ``roadtx graphrequest``)
and does not perform requests or pagination itself.

Supported ``--type`` values (one per file in ``bh/``):

  Nodes:            users, groups, apps, devices, roles, tenants
  Nodes:            ... plus service-principals
  Relationships:    group-owners, group-members, app-owners,
                    service-principal-owners
                    (one file per parent; parent id read from the filename GUID
                     or --group-id / --app-id / --sp-id)
  Assignments:      app-role-assignments  (one file per service principal)
                    role-assignments      (<roleDefinitions.json> <roleAssignments.json>)
"""

import argparse
import json
import os
import re
import sys

GUID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)

# Field descriptors: ("name", kind) where kind is either:
#   "s"          scalar/slice - dropped when empty (Go omitempty)
#   "clean"      object passed through (nulls/empty dropped, {} kept)
#   <schema>     object struct - always emitted, filtered/ordered to the schema
# A <schema> is an ordered list of (name, subschema) with subschema None for a
# scalar leaf or a nested schema list.  This mirrors AzureHound stripping Graph
# subfields it does not model (e.g. an application's web.enabledResponseModes).
# Order matches the AzureHound Go struct declaration order (id emitted first).

# --- nested object schemas (from AzureHound models/azure) ---
EMPLOYEE_ORG_SCHEMA = [("division", None), ("costCenter", None)]
PASSWORD_PROFILE_SCHEMA = [
    ("forceChangePasswordNextSignIn", None),
    ("forceChangePasswordNextSignInWithMfa", None), ("password", None),
]
ONPREM_EXT_SCHEMA = [("extensionAttribute%d" % i, None) for i in range(1, 16)]

API_SCHEMA = [
    ("acceptMappedClaims", None), ("knownClientApplications", None),
    ("oauth2PermissionScopes", None), ("preAuthorizedApplications", None),
    ("requestedAccessTokenVersion", None),
]
INFO_SCHEMA = [
    ("logoUrl", None), ("marketingUrl", None), ("privacyStatementUrl", None),
    ("supportUrl", None), ("termsOfServiceUrl", None),
]
OPTIONAL_CLAIMS_SCHEMA = [("idToken", None), ("accessToken", None), ("saml2Token", None)]
PARENTAL_SCHEMA = [("countriesBlockedForMinors", None), ("legalAgeGroupRule", None)]
REDIRECT_SCHEMA = [("redirectUris", None)]
VERIFIED_PUBLISHER_SCHEMA = [
    ("displayName", None), ("verifiedPublisherId", None), ("addedDateTime", None),
]
IMPLICIT_GRANT_SCHEMA = [("enableIdTokenIssuance", None), ("enableAccessTokenIssuance", None)]
SAML_SSO_SCHEMA = [("relayState", None)]
WEB_SCHEMA = [
    ("homePageUrl", None), ("implicitGrantSettings", IMPLICIT_GRANT_SCHEMA),
    ("logoutUrl", None), ("redirectUris", None),
]

USER_FIELDS = [
    ("accountEnabled", "s"), ("createdDateTime", "s"), ("displayName", "s"),
    ("employeeOrgData", EMPLOYEE_ORG_SCHEMA), ("jobTitle", "s"),
    ("lastPasswordChangeDateTime", "s"), ("mail", "s"), ("mailboxSettings", "clean"),
    ("onPremisesExtensionAttributes", ONPREM_EXT_SCHEMA),
    ("onPremisesSecurityIdentifier", "s"), ("onPremisesSyncEnabled", "s"),
    ("passwordProfile", PASSWORD_PROFILE_SCHEMA), ("userPrincipalName", "s"),
    ("userType", "s"),
]

GROUP_FIELDS = [
    ("allowExternalSenders", "s"), ("assignedLabels", "s"), ("assignedLicenses", "s"),
    ("autoSubscribeNewMembers", "s"), ("classification", "s"), ("createdDateTime", "s"),
    ("deletedDateTime", "s"), ("description", "s"), ("displayName", "s"),
    ("expirationDateTime", "s"), ("groupTypes", "s"), ("hasMembersWithLicenseErrors", "s"),
    ("hideFromAddressLists", "s"), ("hideFromOutlookClients", "s"),
    ("isAssignableToRole", "s"), ("isSubscribedByMail", "s"), ("licenseProcessingState", "s"),
    ("mail", "s"), ("mailEnabled", "s"), ("mailNickname", "s"), ("membershipRule", "s"),
    ("membershipRuleProcessingState", "s"), ("onPremisesLastSyncDateTime", "s"),
    ("onPremisesProvisioningErrors", "s"), ("onPremisesSamAccountName", "s"),
    ("onPremisesSecurityIdentifier", "s"), ("onPremisesSyncEnabled", "s"),
    ("preferredDataLocation", "s"), ("preferredLanguage", "s"), ("proxyAddresses", "s"),
    ("renewedDateTime", "s"), ("resourceBehaviorOptions", "s"),
    ("resourceProvisioningOptions", "s"), ("securityEnabled", "s"),
    ("securityIdentifier", "s"), ("theme", "s"), ("unseenCount", "s"), ("visibility", "s"),
]

# Note: device.onPremisesExtensionAttributes is a struct field that Graph never
# populates (Graph exposes extensionAttributes), so AzureHound always emits {}.
DEVICE_FIELDS = [
    ("accountEnabled", "s"), ("alternativeSecurityIds", "s"),
    ("approximateLastSignInDateTime", "s"), ("complianceExpirationDateTime", "s"),
    ("deviceId", "s"), ("deviceMetadata", "s"), ("deviceVersion", "s"),
    ("displayName", "s"), ("onPremisesExtensionAttributes", ONPREM_EXT_SCHEMA), ("isCompliant", "s"),
    ("isManaged", "s"), ("manufacturer", "s"), ("mdmAppId", "s"), ("model", "s"),
    ("onPremisesLastSyncDateTime", "s"), ("onPremisesSyncEnabled", "s"),
    ("operatingSystem", "s"), ("operatingSystemVersion", "s"), ("physicalIds", "s"),
    ("profileType", "s"), ("systemLabels", "s"), ("trustType", "s"),
]

APP_FIELDS = [
    ("addIns", "s"), ("api", API_SCHEMA), ("appId", "s"), ("applicationTemplateId", "s"),
    ("appRoles", "s"), ("createdDateTime", "s"), ("deletedDateTime", "s"),
    ("description", "s"), ("disabledByMicrosoftStatus", "s"), ("displayName", "s"),
    ("groupMembershipClaims", "s"), ("identifierUris", "s"), ("info", INFO_SCHEMA),
    ("isDeviceOnlyAuthSupported", "s"), ("isFallbackPublicClient", "s"),
    ("keyCredentials", "s"), ("logo", "s"), ("notes", "s"),
    ("oauth2RequiredPostResponse", "s"), ("optionalClaims", OPTIONAL_CLAIMS_SCHEMA),
    ("parentalControlSettings", PARENTAL_SCHEMA), ("passwordCredentials", "s"),
    ("publicClient", REDIRECT_SCHEMA), ("publisherDomain", "s"), ("requiredResourceAccess", "s"),
    ("signInAudience", "s"), ("spa", REDIRECT_SCHEMA), ("tags", "s"), ("tokenEncryptionKeyId", "s"),
    ("verifiedPublisher", VERIFIED_PUBLISHER_SCHEMA), ("web", WEB_SCHEMA),
]

ROLE_FIELDS = [
    ("description", "s"), ("displayName", "s"), ("isBuiltIn", "s"), ("isEnabled", "s"),
    ("resourceScopes", "s"), ("rolePermissions", "s"), ("templateId", "s"),
    ("version", "s"),
]

SERVICE_PRINCIPAL_FIELDS = [
    ("accountEnabled", "s"), ("addIns", "s"), ("alternativeNames", "s"),
    ("appDescription", "s"), ("appDisplayName", "s"), ("appId", "s"),
    ("applicationTemplateId", "s"), ("appOwnerOrganizationId", "s"),
    ("appRoleAssignmentRequired", "s"), ("appRoles", "s"), ("deletedDateTime", "s"),
    ("description", "s"), ("disabledByMicrosoftStatus", "s"), ("displayName", "s"),
    ("homepage", "s"), ("info", INFO_SCHEMA), ("keyCredentials", "s"),
    ("loginUrl", "s"), ("logoutUrl", "s"), ("notes", "s"),
    ("notificationEmailAddresses", "s"), ("oauth2PermissionScopes", "s"),
    ("passwordCredentials", "s"), ("preferredSingleSignOnMode", "s"),
    ("replyUrls", "s"), ("samlSingleSignOnSettings", SAML_SSO_SCHEMA),
    ("servicePrincipalNames", "s"), ("servicePrincipalType", "s"),
    ("signInAudience", "s"), ("tags", "s"), ("tokenEncryptionKeyId", "s"),
    ("verifiedPublisher", VERIFIED_PUBLISHER_SCHEMA),
]

NODE_TYPES = {
    "users": ("AZUser", USER_FIELDS),
    "groups": ("AZGroup", GROUP_FIELDS),
    "apps": ("AZApp", APP_FIELDS),
    "devices": ("AZDevice", DEVICE_FIELDS),
    "roles": ("AZRole", ROLE_FIELDS),
    "service-principals": ("AZServicePrincipal", SERVICE_PRINCIPAL_FIELDS),
}

# AzureHound serialises a zero-valued Application struct for the (unexpanded)
# directoryScope of a directory role assignment; reproduce it verbatim.
EMPTY_APPLICATION = {
    "id": "", "api": {}, "info": {}, "optionalClaims": {},
    "parentalControlSettings": {}, "publicClient": {}, "spa": {},
    "verifiedPublisher": {}, "web": {"implicitGrantSettings": {}},
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def load_json(path):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError:
        sys.exit(f"[!] Input file not found: {path}")
    except json.JSONDecodeError as exc:
        sys.exit(f"[!] {path} is not valid JSON: {exc}")


def graph_objects(raw):
    """Normalise a raw Graph response into a list of objects."""
    if isinstance(raw, dict) and isinstance(raw.get("value"), list):
        return raw["value"]
    if isinstance(raw, list):
        return raw
    if isinstance(raw, dict):
        return [raw]
    sys.exit("[!] Unexpected input structure: expected a Graph response object or list.")


def expand_input_paths(paths):
    expanded = []
    for path in paths:
        if os.path.isdir(path):
            for root, _, files in os.walk(path):
                for filename in sorted(files):
                    expanded.append(os.path.join(root, filename))
        elif os.path.isfile(path):
            expanded.append(path)
        else:
            sys.exit(f"[!] Input path not found: {path}")
    if not expanded:
        sys.exit("[!] No JSON input files found.")
    return expanded


def load_objects(paths):
    objects = []
    for path in paths:
        objects.extend(graph_objects(load_json(path)))
    return objects


def is_empty(value):
    """Go ``omitempty`` semantics: null, "", false, 0 and [] are empty."""
    return value is None or value == [] or value == "" or value is False or value == 0


def _drop(value, drop_empty_dict):
    return is_empty(value) or (drop_empty_dict and value == {})


def clean(value, drop_empty_dict=False):
    """Recursively drop empty members from a Graph object.

    ``drop_empty_dict=False`` keeps ``{}`` (node struct fields such as a user's
    mailboxSettings keep empty sub-objects).  ``drop_empty_dict=True`` drops
    ``{}`` (embedded owner/member directory objects lose empty map fields).
    """
    if isinstance(value, dict):
        out = {}
        for key, val in value.items():
            val = clean(val, drop_empty_dict)
            if not _drop(val, drop_empty_dict):
                out[key] = val
        return out
    if isinstance(value, list):
        out = []
        for item in value:
            item = clean(item, drop_empty_dict)
            if not _drop(item, drop_empty_dict):
                out.append(item)
        return out
    return value


def wrap(data):
    return {"data": data, "meta": {"type": "azure", "version": 5, "count": len(data)}}


def group_id_from_filename(path):
    match = GUID_RE.search(os.path.basename(path))
    return match.group(0) if match else None


def infer_tenant_id(objects, explicit):
    if explicit:
        return explicit
    for obj in objects:
        for key in ("tenantId", "organizationId", "principalOrganizationId"):
            if isinstance(obj, dict) and obj.get(key):
                return obj[key]
    return None


# ---------------------------------------------------------------------------
# Node conversion (users, groups, apps, devices, roles)
# ---------------------------------------------------------------------------
def apply_schema(value, schema):
    """Filter/order an object to a nested struct schema (always returns a dict).

    Scalar leaves are kept only when non-empty; nested object leaves are always
    emitted (empty -> {}), mirroring Go struct serialisation.
    """
    src = value if isinstance(value, dict) else {}
    out = {}
    for name, sub in schema:
        if sub is None:
            val = clean(src.get(name))
            if not is_empty(val):
                out[name] = val
        else:
            out[name] = apply_schema(src.get(name), sub)
    return out


def build_node(obj, fields, tenant_id, tenant_name):
    """Build a node ``data`` dict, preserving AzureHound field order."""
    node = {}
    # DirectoryObject/Entity id is always emitted first.
    node["id"] = obj.get("id", "")
    for name, kind in fields:
        if kind == "s":
            # clean() drops null/empty members nested inside slice elements
            # (e.g. keyCredentials[].key == null), like the element structs do.
            val = clean(obj.get(name))
            if not is_empty(val):
                node[name] = val
        elif kind == "clean":
            # Object passed through as-is (empty sub-objects preserved).
            val = obj.get(name)
            node[name] = clean(val) if isinstance(val, dict) else {}
        else:
            # Object struct field with a schema (always emitted).
            node[name] = apply_schema(obj.get(name), kind)
    # Wrapper appends tenantId/tenantName unconditionally (no omitempty).
    node["tenantId"] = tenant_id if tenant_id is not None else ""
    node["tenantName"] = tenant_name if tenant_name is not None else ""
    return node


def convert_nodes(objects, kind, fields, tenant_id, tenant_name):
    tenant_id = infer_tenant_id(objects, tenant_id)
    if tenant_id is None:
        print("[*] No tenantId found; pass --tenant-id (tenantId will be empty).", file=sys.stderr)
    records = [
        {"kind": kind, "data": build_node(obj, fields, tenant_id, tenant_name)}
        for obj in objects
    ]
    return wrap(records)


# ---------------------------------------------------------------------------
# Tenant conversion (/beta/organization -> AZTenant)
# ---------------------------------------------------------------------------
def convert_tenant(objects, tenant_name):
    """Mirror AzureHound's Organization.ToTenant() mapping."""
    records = []
    for org in objects:
        verified = org.get("verifiedDomains") or []
        domains = [d.get("name") for d in verified if d.get("name")]
        default_domain = next((d.get("name") for d in verified if d.get("isDefault")), None)

        data = {}
        if org.get("country"):
            data["country"] = org["country"]
        if org.get("countryLetterCode"):
            data["countryCode"] = org["countryLetterCode"]
        if default_domain:
            data["defaultDomain"] = default_domain
        if org.get("displayName") or tenant_name:
            data["displayName"] = org.get("displayName") or tenant_name
        if domains:
            data["domains"] = domains
        if org.get("id"):
            data["id"] = f"/tenants/{org['id']}"       # BloodHound tenant node id
            data["tenantId"] = org["id"]
        if org.get("tenantType"):
            data["tenantType"] = org["tenantType"]
        data["collected"] = True
        records.append({"kind": "AZTenant", "data": data})
    return wrap(records)


# ---------------------------------------------------------------------------
# Relationship conversion (group-owners, group-members, app-owners)
# ---------------------------------------------------------------------------
def convert_relationship(input_files, override_id, kind, parent_key, container_key, item_key):
    """One input file per parent; parent id from the filename (or override)."""
    if override_id and len(input_files) != 1:
        sys.exit("[!] The id override only works with a single input file.")
    records = []
    for path in input_files:
        parent_id = override_id or group_id_from_filename(path)
        if not parent_id:
            sys.exit(
                f"[!] Could not determine the {parent_key} for {path}. "
                "Include the GUID in the filename or pass it explicitly."
            )
        related = graph_objects(load_json(path))
        # Embedded directory objects drop empty map fields to match BloodHound.
        items = [
            {parent_key: parent_id, item_key: clean(obj, drop_empty_dict=True)}
            for obj in related
        ]
        container = items if items else None  # explicit null when none
        records.append({"kind": kind, "data": {container_key: container, parent_key: parent_id}})
    return wrap(records)


# ---------------------------------------------------------------------------
# App role assignments (flat records, appId from the parent service principal)
# ---------------------------------------------------------------------------
APP_ROLE_ASSIGNMENT_FIELDS = [
    "appRoleId", "createdDateTime", "id", "principalDisplayName",
    "principalId", "principalType", "resourceDisplayName", "resourceId",
]


def convert_app_role_assignments(input_files, override_app_id, tenant_id):
    if override_app_id and len(input_files) != 1:
        sys.exit("[!] --app-id only works with a single input file.")
    records = []
    for path in input_files:
        app_id = override_app_id or group_id_from_filename(path)
        if not app_id:
            sys.exit(
                f"[!] Could not determine the appId for {path}. "
                "Include the GUID in the filename or use --app-id."
            )
        objects = graph_objects(load_json(path))
        this_tenant = infer_tenant_id(objects, tenant_id)
        for obj in objects:
            data = {}
            for f in APP_ROLE_ASSIGNMENT_FIELDS:      # struct/declaration order
                if not is_empty(obj.get(f)):
                    data[f] = obj[f]
            data["appId"] = app_id
            data["tenantId"] = this_tenant if this_tenant is not None else ""
            records.append({"kind": "AZAppRoleAssignment", "data": data})
    return wrap(records)


# ---------------------------------------------------------------------------
# Directory role assignments (one record per role definition)
# ---------------------------------------------------------------------------
def build_role_assignment(a):
    """Reproduce AzureHound's UnifiedRoleAssignment serialisation.

    Real values (id, roleDefinitionId, principalId, directoryScopeId) plus the
    always-emitted empty struct fields roleDefinition / directoryScope /
    appScope.
    """
    entry = {"id": a.get("id", "")}
    for f in ("roleDefinitionId", "principalId", "directoryScopeId"):
        if not is_empty(a.get(f)):
            entry[f] = a[f]
    # Note: app-scoped assignments (directoryScopeId != "/") would be rewritten
    # by AzureHound to "/<appId>" using $expand=directoryScope data, which is
    # not present in a plain roleAssignments response; the raw value is kept.
    entry["roleDefinition"] = {"id": ""}
    entry["directoryScope"] = dict(EMPTY_APPLICATION)
    entry["appScope"] = {"id": ""}
    return entry


def convert_role_assignments(roles_objs, assignment_objs, tenant_id):
    """Join role assignments onto every role definition (one record each)."""
    tenant_id = infer_tenant_id(assignment_objs, tenant_id)
    grouped = {}
    for a in assignment_objs:
        rid = a.get("roleDefinitionId")
        if rid is not None:
            grouped.setdefault(rid, []).append(build_role_assignment(a))
    records = []
    for role in roles_objs:
        rid = role.get("id")
        if rid is None:
            continue
        assignments = grouped.get(rid)
        data = {
            "roleAssignments": assignments if assignments else None,
            "roleDefinitionId": rid,
            "tenantId": tenant_id if tenant_id is not None else "",
        }
        records.append({"kind": "AZRoleAssignment", "data": data})
    return wrap(records)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def write_output(result, output_path, label):
    try:
        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=2)
            fh.write("\n")
    except OSError as exc:
        sys.exit(f"[!] Could not write output file {output_path}: {exc}")
    print(f"[+] Wrote {result['meta']['count']} {label} record(s) to {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Convert raw Microsoft Graph JSON into BloodHound (Azure) JSON.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("file", nargs="+", help="Input file(s) or directory(ies)")
    parser.add_argument(
        "--type", required=True,
        choices=[
            "users", "groups", "apps", "devices", "roles", "tenants",
            "service-principals",
            "group-owners", "group-members", "app-owners",
            "service-principal-owners",
            "app-role-assignments", "role-assignments",
        ],
        help="Conversion type.",
    )
    parser.add_argument("--tenant-id", help="Tenant GUID stored on nodes/assignments.")
    parser.add_argument("--tenant-name", default="My Tenant", help='Tenant display name (default: "My Tenant").')
    parser.add_argument("--group-id", help="Group GUID for a single group-owners/members file.")
    parser.add_argument("--app-id", help="App/SP GUID for a single app-owners/app-role-assignments file.")
    parser.add_argument("--sp-id", help="Service principal GUID for a single service-principal-owners file.")
    args = parser.parse_args()

    orig_inputs = args.file
    inputs = expand_input_paths(orig_inputs)
    output_path = "AZ" + args.type + ".json"
    t = args.type

    if t in NODE_TYPES:
        kind, fields = NODE_TYPES[t]
        result = convert_nodes(load_objects(inputs), kind, fields,
                               args.tenant_id, args.tenant_name)
    elif t == "tenants":
        result = convert_tenant(load_objects(inputs), args.tenant_name)
    elif t == "group-owners":
        result = convert_relationship(inputs, args.group_id, "AZGroupOwner", "groupId", "owners", "owner")
    elif t == "group-members":
        result = convert_relationship(inputs, args.group_id, "AZGroupMember", "groupId", "members", "member")
    elif t == "app-owners":
        result = convert_relationship(inputs, args.app_id, "AZAppOwner", "appId", "owners", "owner")
    elif t == "service-principal-owners":
        result = convert_relationship(inputs, args.sp_id, "AZServicePrincipalOwner", "servicePrincipalId", "owners", "owner")
    elif t == "app-role-assignments":
        result = convert_app_role_assignments(inputs, args.app_id, args.tenant_id)
    elif t == "role-assignments":
        if len(inputs) != 2:
            parser.error("--type role-assignments expects two input files: <roleDefinitions> <roleAssignments>")
        result = convert_role_assignments(
            graph_objects(load_json(inputs[0])),
            graph_objects(load_json(inputs[1])),
            args.tenant_id,
        )
    else:  # pragma: no cover
        parser.error(f"unsupported type {t}")

    write_output(result, output_path, t)


if __name__ == "__main__":
    main()
