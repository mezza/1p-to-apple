#!/usr/bin/env python3
"""
1Password (1PUX) to Apple Passwords CSV Migrator
=================================================

Usage:
    python3 migrate.py <path-to-export.1pux> [--output passwords.csv] [--report skipped.txt]

Examples:
    python3 migrate.py ~/Downloads/D4RI47B7.1pux
    python3 migrate.py export.1pux --output my_passwords.csv --report my_skipped.txt

This script:
  1. Opens a .1pux file (ZIP archive containing export.data JSON)
  2. Extracts login items (category 001) and password items (category 005)
  3. Writes a CSV compatible with Apple Passwords import:
     Title, URL, Username, Password, Notes, OTPAuth
  4. Generates a report of skipped/unmigrated items

Requirements: Python 3.6+ (stdlib only, no pip packages needed)
"""

import csv
import io
import json
import sys
import zipfile
from argparse import ArgumentParser
from collections import defaultdict

# 1Password category UUIDs
CATEGORIES = {
    "001": "Login",
    "002": "Credit Card",
    "003": "Secure Note",
    "004": "Identity",
    "005": "Password",
    "006": "Document",
    "100": "Software License",
    "101": "Bank Account",
    "102": "Database",
    "103": "Driver's License",
    "104": "Outdoor License",
    "105": "Membership",
    "106": "Passport",
    "107": "Rewards Program",
    "108": "Social Security Number",
    "109": "Wireless Router",
    "110": "Server",
    "111": "Email Account",
    "112": "API Credential",
    "113": "Medical Record",
    "114": "SSH Key",
    "115": "Crypto Wallet",
}

# Categories with native login fields
LOGIN_CATEGORIES = {"001", "005"}

# All categories are now migratable — non-login items are stored as
# Apple Passwords entries with all their fields dumped into Notes.


def extract_export_data(pux_path: str) -> dict:
    """Extract and parse export.data JSON from a .1pux ZIP file."""
    with zipfile.ZipFile(pux_path, "r") as zf:
        names = zf.namelist()
        # Find export.data (could be at root or in a subdirectory)
        data_file = None
        for name in names:
            if name.endswith("export.data"):
                data_file = name
                break
        if not data_file:
            raise FileNotFoundError(
                f"No 'export.data' found in {pux_path}. Files: {names}"
            )
        with zf.open(data_file) as f:
            return json.load(f)


def get_login_fields(item: dict) -> tuple:
    """Extract (username, password) from loginFields using designation."""
    username = ""
    password = ""
    details = item.get("details", {})

    for field in details.get("loginFields", []) or []:
        if field is None:
            continue
        designation = field.get("designation", "")
        value = field.get("value", "") or ""
        if designation == "username" and value:
            username = value
        elif designation == "password" and value:
            password = value

    # Fallback: check details.password (used by Password items, category 005)
    if not password:
        password = details.get("password", "") or ""

    return username, password


def get_urls(item: dict) -> list:
    """Extract all URLs from an item."""
    overview = item.get("overview", {})
    urls = []

    # Primary URL
    primary = overview.get("url", "") or ""
    if primary:
        urls.append(primary)

    # Additional URLs
    for url_obj in overview.get("urls", []) or []:
        if url_obj is None:
            continue
        u = url_obj.get("url", "") or ""
        if u and u not in urls:
            urls.append(u)

    return urls


def get_totp(item: dict) -> str:
    """Extract TOTP/OTPAuth URI from sections."""
    details = item.get("details", {})
    for section in details.get("sections", []) or []:
        if section is None:
            continue
        for field in section.get("fields", []) or []:
            if field is None:
                continue
            # TOTP fields have id containing "TOTP" or type "otp"
            field_id = (field.get("id", "") or "").upper()
            field_value = field.get("value", {})

            # The value for OTP fields is typically a string starting with otpauth://
            # or it could be nested as {"totp": "otpauth://..."}
            if isinstance(field_value, str) and field_value.startswith("otpauth://"):
                return field_value
            if isinstance(field_value, dict):
                totp = field_value.get("totp", "") or ""
                if totp.startswith("otpauth://"):
                    return totp
            # Check if field references OTP by id
            if "TOTP" in field_id or field_id == "ONE_TIME_PASSWORD":
                if isinstance(field_value, str) and field_value:
                    # Might be a raw secret, wrap it
                    if field_value.startswith("otpauth://"):
                        return field_value
                    # Raw secret — construct otpauth URI
                    title = item.get("overview", {}).get("title", "unknown")
                    return f"otpauth://totp/{title}?secret={field_value}&issuer={title}"
    return ""


def get_title(item: dict) -> str:
    return (item.get("overview", {}).get("title", "") or "").strip()


def get_notes(item: dict) -> str:
    return (item.get("details", {}).get("notesPlain", "") or "").strip()


def extract_all_fields(item: dict, cat: str) -> str:
    """Extract ALL fields from non-login items into a readable text block.
    Handles credit cards, bank accounts, identities, etc."""
    lines = []
    details = item.get("details", {})

    # Credit Card specific fields
    if cat == "002":
        for key, label in [("ccnum", "Card Number"), ("cvv", "CVV"),
                           ("expiry", "Expiry"), ("cardholder", "Cardholder"),
                           ("pin", "PIN"), ("bank", "Bank"),
                           ("type", "Type"), ("validFrom", "Valid From")]:
            val = details.get(key, "") or ""
            if val:
                # Expiry might be epoch
                if key == "expiry" and str(val).isdigit():
                    import datetime
                    try:
                        dt = datetime.datetime.fromtimestamp(int(val))
                        val = dt.strftime("%m/%Y")
                    except Exception:
                        pass
                lines.append(f"{label}: {val}")

    # Bank Account specific
    if cat == "101":
        for key, label in [("bankName", "Bank"), ("accountType", "Type"),
                           ("routingNo", "Routing"), ("accountNo", "Account"),
                           ("swift", "SWIFT"), ("iban", "IBAN"),
                           ("branchAddress", "Branch"), ("branchPhone", "Phone")]:
            val = details.get(key, "") or ""
            if val:
                lines.append(f"{label}: {val}")

    # Identity specific
    if cat == "004":
        for key, label in [("firstname", "First Name"), ("lastname", "Last Name"),
                           ("initial", "Initial"), ("gender", "Gender"),
                           ("birthdate", "Birth Date"), ("occupation", "Occupation"),
                           ("company", "Company"), ("department", "Department"),
                           ("jobtitle", "Job Title"), ("address", "Address"),
                           ("email", "Email"), ("phone", "Phone"),
                           ("cell", "Cell"), ("website", "Website")]:
            val = details.get(key, "") or ""
            if val:
                lines.append(f"{label}: {val}")

    # Generic: grab all section fields (works for all types)
    for section in details.get("sections", []) or []:
        if section is None:
            continue
        section_title = section.get("title", "") or ""
        for field in section.get("fields", []) or []:
            if field is None:
                continue
            ftitle = field.get("title", "") or field.get("id", "") or ""
            fvalue = field.get("value", "")
            if isinstance(fvalue, dict):
                # Flatten dict values
                parts = [f"{k}: {v}" for k, v in fvalue.items() if v]
                fvalue = ", ".join(parts) if parts else ""
            if fvalue and str(fvalue).strip():
                label = f"{section_title} > {ftitle}" if section_title else ftitle
                lines.append(f"{label}: {fvalue}")

    # Also grab loginFields if any exist on non-login items
    for field in details.get("loginFields", []) or []:
        if field is None:
            continue
        val = field.get("value", "") or ""
        name = field.get("name", "") or field.get("designation", "") or ""
        if val:
            lines.append(f"{name}: {val}")

    return "\n".join(lines)


def get_extra_fields(item: dict) -> list:
    """Collect non-standard fields from sections for notes."""
    extras = []
    details = item.get("details", {})
    for section in details.get("sections", []) or []:
        if section is None:
            continue
        section_title = section.get("title", "") or ""
        for field in section.get("fields", []) or []:
            if field is None:
                continue
            fid = (field.get("id", "") or "").upper()
            # Skip TOTP (handled separately)
            if "TOTP" in fid or fid == "ONE_TIME_PASSWORD":
                continue
            ftitle = field.get("title", "") or field.get("id", "") or ""
            fvalue = field.get("value", "")
            if isinstance(fvalue, dict):
                # Some fields store complex values
                fvalue = json.dumps(fvalue)
            if fvalue and str(fvalue).strip():
                label = f"{section_title}: {ftitle}" if section_title else ftitle
                extras.append(f"{label}: {fvalue}")
    return extras


def process_items(data: dict) -> tuple:
    """
    Process all items from export data.
    Returns (migrated_rows, skipped_items).
    migrated_rows: list of dicts with Title, URL, Username, Password, Notes, OTPAuth
    skipped_items: list of dicts with title, category, vault, reason
    """
    migrated = []
    skipped = []

    for account in data.get("accounts", []) or []:
        account_name = account.get("attrs", {}).get("accountName", "Unknown")
        for vault in account.get("vaults", []) or []:
            vault_name = vault.get("attrs", {}).get("name", "Unknown")
            for item in vault.get("items", []) or []:
                cat = item.get("categoryUuid", "")
                title = get_title(item)
                state = item.get("state", "active")

                # Skip only trashed items; archived items still migrate
                if state == "trashed":
                    skipped.append({
                        "title": title,
                        "category": CATEGORIES.get(cat, f"Unknown ({cat})"),
                        "vault": vault_name,
                        "reason": "Item is trashed",
                    })
                    continue

                username, password = get_login_fields(item)
                urls = get_urls(item)
                totp = get_totp(item)
                notes = get_notes(item)
                extra_fields = get_extra_fields(item)
                cat_name = CATEGORIES.get(cat, f"Unknown ({cat})")

                # For non-login categories, extract all fields into notes
                if cat not in LOGIN_CATEGORIES:
                    all_fields = extract_all_fields(item, cat)
                    if all_fields:
                        header = f"[{cat_name}]\n"
                        if notes:
                            notes = header + notes + "\n\n" + all_fields
                        else:
                            notes = header + all_fields
                    elif not notes:
                        # Tag it so we know what type it was
                        notes = f"[{cat_name}]"

                # Mark archived items in notes
                if state == "archived":
                    notes = f"[Archived]\n{notes}" if notes else "[Archived]"

                # Append extra fields to notes
                if extra_fields:
                    if notes:
                        notes += "\n\n--- Additional Fields ---\n"
                    notes += "\n".join(extra_fields)

                primary_url = urls[0] if urls else ""

                # Append additional URLs to notes
                if len(urls) > 1:
                    url_lines = "\n".join(urls[1:])
                    if notes:
                        notes += f"\n\n--- Additional URLs ---\n{url_lines}"
                    else:
                        notes = f"--- Additional URLs ---\n{url_lines}"

                migrated.append({
                    "Title": title,
                    "URL": primary_url,
                    "Username": username,
                    "Password": password,
                    "Notes": notes,
                    "OTPAuth": totp,
                })

    return migrated, skipped


def write_csv(rows: list, output_path: str):
    """Write Apple Passwords compatible CSV."""
    fieldnames = ["Title", "URL", "Username", "Password", "Notes", "OTPAuth"]
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def write_report(skipped: list, report_path: str):
    """Write a human-readable report of skipped items."""
    # Group by category
    by_category = defaultdict(list)
    for item in skipped:
        by_category[item["category"]].append(item)

    with open(report_path, "w", encoding="utf-8") as f:
        f.write("=" * 60 + "\n")
        f.write("1Password → Apple Passwords: Skipped Items Report\n")
        f.write("=" * 60 + "\n\n")
        f.write(f"Total skipped: {len(skipped)}\n\n")

        for category, items in sorted(by_category.items()):
            f.write(f"--- {category} ({len(items)} items) ---\n")
            for item in items:
                f.write(f"  • {item['title']}")
                if item["vault"]:
                    f.write(f"  [vault: {item['vault']}]")
                f.write(f"  — {item['reason']}\n")
            f.write("\n")


def main():
    parser = ArgumentParser(description="Migrate 1Password .1pux export to Apple Passwords CSV")
    parser.add_argument("input", help="Path to .1pux file")
    parser.add_argument("--output", "-o", default="passwords.csv", help="Output CSV path (default: passwords.csv)")
    parser.add_argument("--report", "-r", default="skipped_items.txt", help="Skipped items report path (default: skipped_items.txt)")
    args = parser.parse_args()

    print(f"📂 Reading {args.input}...")
    data = extract_export_data(args.input)

    migrated, skipped = process_items(data)

    write_csv(migrated, args.output)
    print(f"✅ Exported {len(migrated)} items → {args.output}")

    write_report(skipped, args.report)
    print(f"📋 Skipped {len(skipped)} items → {args.report}")

    # Summary
    print(f"\n{'='*40}")
    print(f"  Migrated:  {len(migrated)} logins/passwords")
    print(f"  Skipped:   {len(skipped)} items")
    print(f"{'='*40}")
    if skipped:
        cats = defaultdict(int)
        for s in skipped:
            cats[s["category"]] += 1
        print("  Skipped breakdown:")
        for cat, count in sorted(cats.items(), key=lambda x: -x[1]):
            print(f"    {cat}: {count}")


if __name__ == "__main__":
    main()
