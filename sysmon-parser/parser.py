#!/usr/bin/env python3
"""Parse a Sysmon XML file and print the key Event ID 1 fields as JSON."""

import argparse
import csv
import json
import sys
import xml.etree.ElementTree as ET

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"

FIELDS = [
    "UtcTime",
    "Image",
    "CommandLine",
    "User",
    "IntegrityLevel",
    "ParentImage",
    "ParentCommandLine",
    "Hashes",
]

# Column order for tabular/lined output (jsonl keeps dict insertion order, csv uses this explicitly).
OUTPUT_FIELDS = [
    "EventID",
    "UtcTime",
    "Image",
    "CommandLine",
    "User",
    "IntegrityLevel",
    "ParentImage",
    "ParentCommandLine",
    "Computer",
    "Hashes",
]


def parse_event(event: ET.Element) -> dict:
    event_id = int(event.findtext(f"{NS}System/{NS}EventID"))
    computer = event.findtext(f"{NS}System/{NS}Computer")

    result = {"EventID": event_id, "Computer": computer}
    for field in FIELDS:
        data = event.find(f"{NS}EventData/{NS}Data[@Name='{field}']")
        result[field] = data.text if data is not None else None

    return result


def iter_events(path: str):
    # ET.parse() reads the entire file into one in-memory tree before
    # returning, which doesn't scale to large Sysmon exports (potentially
    # millions of events). iterparse() streams the file instead, firing an
    # "end" callback each time an element closes. We only act on </Event>
    # closes, and clear() each event's children/text right after reading it,
    # so memory usage stays roughly flat regardless of file size instead of
    # growing with the number of events.
    for _, element in ET.iterparse(path, events=("end",)):
        if element.tag == f"{NS}Event":
            yield parse_event(element)
            element.clear()


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Parse a Sysmon XML file and print Event ID 1 fields as JSON."
    )
    parser.add_argument("path", help="Path to the Sysmon XML file")
    parser.add_argument(
        "--image",
        help="Only include events whose Image contains this substring (case-insensitive)",
    )
    parser.add_argument(
        "--user",
        help="Only include events whose User contains this substring (case-insensitive)",
    )
    parser.add_argument(
        "--integrity-level",
        choices=["Untrusted", "Low", "Medium", "High", "System"],
        type=str.title,  # normalizes casing, e.g. "high" -> "High", before the choices check
        help="Only include events with this IntegrityLevel",
    )
    parser.add_argument(
        "--format",
        choices=["json", "jsonl", "csv"],
        default="json",
        help="Output format: json (array, default), jsonl (one object per line), or csv",
    )
    return parser


def event_matches(
    event: dict, image: str | None, user: str | None, integrity_level: str | None
) -> bool:
    if image is not None:
        value = event.get("Image")
        if value is None or image.lower() not in value.lower():
            return False
    if user is not None:
        value = event.get("User")
        if value is None or user.lower() not in value.lower():
            return False
    if integrity_level is not None:
        if event.get("IntegrityLevel") != integrity_level:
            return False
    return True


def main() -> int:
    args = build_arg_parser().parse_args()

    parsed = [
        event
        for event in iter_events(args.path)
        if event_matches(event, args.image, args.user, args.integrity_level)
    ]

    if args.format == "json":
        print(json.dumps(parsed, indent=2))
    elif args.format == "jsonl":
        for event in parsed:
            print(json.dumps(event))
    elif args.format == "csv":
        writer = csv.DictWriter(sys.stdout, fieldnames=OUTPUT_FIELDS)
        writer.writeheader()
        writer.writerows(parsed)

    return 0


if __name__ == "__main__":
    sys.exit(main())
