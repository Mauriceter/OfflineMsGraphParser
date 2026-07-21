#!/usr/bin/env python3

import argparse
import json
import glob
import os
from textwrap import shorten


def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_service_principals(path):

    index = {}

    if os.path.isdir(path):
        files = glob.glob(
            os.path.join(path, "*")
        )
    else:
        files = glob.glob(path)


    print(f"[+] Loading {len(files)} service principal files")


    for filename in files:

        content = load_json(filename)

        if isinstance(content, dict) and "data" in content:
            objects = content["data"]

        elif isinstance(content, dict) and "value" in content:
            objects = content["value"]

        elif isinstance(content, list):
            objects = content

        else:
            objects = [content]


        for item in objects:

            if item.get("kind") == "AZServicePrincipal":
                sp = item.get("data", {})
            else:
                sp = item


            sp_id = sp.get("id")

            if sp_id:
                index[sp_id] = sp


    print(
        f"[+] Indexed {len(index)} service principals"
    )

    return index



def load_assignments(path):

    data = load_json(path)

    return data.get(
        "value",
        []
    )



def find_app_role(sp, app_role_id):

    for role in sp.get(
        "appRoles",
        []
    ):

        if role.get("id") == app_role_id:
            return {
                "name": role.get(
                    "displayName"
                ),
                "description": role.get(
                    "description"
                )
            }


    return {
        "name": "Unknown",
        "description": ""
    }



def print_table(rows):

    headers = [
        "Principal",
        "AppId",
        "Resource",
        "Role",
        "Description"
    ]


    widths = [
        35,
        38,
        35,
        30,
        60
    ]


    line = " | ".join(
        h.ljust(w)
        for h, w in zip(headers, widths)
    )

    print()
    print(line)
    print("-" * len(line))


    for r in rows:

        print(
            " | ".join(
                shorten(str(v), width=w)
                .ljust(w)
                for v, w in zip(r, widths)
            )
        )



def main():

    parser = argparse.ArgumentParser(
        description="List Azure App Role Assignments"
    )


    parser.add_argument(
        "--approles",
        required=True,
        help="Path to app role JSON files (can be a directory or glob pattern)"
    )


    parser.add_argument(
        "--serviceprincipals",
        required=True,
        help="Path to service principal JSON files (can be a directory or glob pattern)"
    )


    args = parser.parse_args()


    sps = load_service_principals(
        args.serviceprincipals
    )


    assignments = load_assignments(
        args.approles
    )


    rows = []


    for assignment in assignments:

        resource_id = assignment.get(
            "resourceId"
        )


        sp = sps.get(
            resource_id,
            {}
        )


        role = find_app_role(
            sp,
            assignment.get(
                "appRoleId"
            )
        )


        rows.append(
            [
                assignment.get(
                    "principalDisplayName",
                    ""
                ),

                sp.get(
                    "appId",
                    ""
                ),

                assignment.get(
                    "resourceDisplayName",
                    ""
                ),

                role["name"],

                role["description"]
            ]
        )


    print_table(rows)


if __name__ == "__main__":
    main()