#!/usr/bin/env python3

import json
import argparse


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument("input", help="me/transitiveMemberOf JSON")
    parser.add_argument("output", help="BloodHound AZGroupMember JSON")

    parser.add_argument("--user-id", required=True)
    parser.add_argument("--display-name", required=True)
    parser.add_argument("--created", required=True)
    parser.add_argument("--odata-type", default="#microsoft.graph.user")

    args = parser.parse_args()

    with open(args.input, "r", encoding="utf-8") as f:
        src = json.load(f)

    output = {
        "data": [],
        "meta": {
            "type": "azure",
            "version": 5,
            "count": len(src["value"])
        }
    }

    for group in src["value"]:
        gid = group["id"]

        output["data"].append({
            "kind": "AZGroupMember",
            "data": {
                "groupId": gid,
                "members": [{
                    "groupId": gid,
                    "member": {
                        "@odata.type": args.odata_type,
                        "id": args.user_id,
                        "displayName": args.display_name,
                        "createdDateTime": args.created
                    }
                }]
            }
        })

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=4)


if __name__ == "__main__":
    main()