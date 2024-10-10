# Usage: python3 export.py -a app name

import argparse
import csv
import json
import os
import sys
import time
import urllib.parse

import httpx
import joern2sarif.lib.convert as convertLib
from json2xml import json2xml
from rich.console import Console
from rich.progress import Progress

import config
from common import extract_org_id, get_all_apps, get_findings_url, headers

console = Console(color_system="auto")


def export_csv(app_list, findings, report_file):
    if not os.path.exists(report_file):
        with open(report_file, "w", newline="") as csvfile:
            reportwriter = csv.writer(
                csvfile,
                dialect="excel",
                delimiter=",",
                quotechar='"',
                quoting=csv.QUOTE_MINIMAL,
            )
            reportwriter.writerow(
                [
                    "App",
                    "App Group",
                    "Finding ID",
                    "Type",
                    "Category",
                    "OWASP Category",
                    "Severity",
                    "Source Method",
                    "Sink Method",
                    "Source File",
                    "Version First Seen",
                    "Scan First Seen",
                    "Internal ID",
                    "CVSS 3.1 Rating",
                    "CVSS Score",
                    "Reachability",
                    "PACKAGE COMPONENT",
                    "CVE",
                ]
            )
    with open(report_file, "a", newline="") as csvfile:
        reportwriter = csv.writer(
            csvfile,
            dialect="excel",
            delimiter=",",
            quotechar='"',
            quoting=csv.QUOTE_MINIMAL,
        )
        for app in app_list:
            app_name = app.get("name")
            tags = app.get("tags")
            app_group = ""
            if tags:
                for tag in tags:
                    if tag.get("key") == "group":
                        app_group = tag.get("value")
                        break
            source_method = ""
            sink_method = ""
            cvss_31_severity_rating = ""
            cvss_score = ""
            reachability = ""
            package_component = ""
            cve = ""
            files_loc_list = set()
            # Find the source, sink, and other tags
            for afinding in findings:
                details = afinding.get("details", {})
                source_method = details.get("source_method", "")
                sink_method = details.get("sink_method", "")
                tags = afinding.get("tags")
                if tags:
                    for tag in tags:
                        if tag.get("key") == "cvss_31_severity_rating":
                            cvss_31_severity_rating = tag.get("value")
                        elif tag.get("key") == "cvss_score":
                            cvss_score = tag.get("value")
                        elif tag.get("key") == "reachability":
                            reachability = tag.get("value")
                        elif tag.get("key") == "package_component":
                            package_component = tag.get("value")
                        elif tag.get("key") == "cve":
                            cve = tag.get("value")
                if details.get("file_locations"):
                    files_loc_list.update(details.get("file_locations"))
                if not source_method or not sink_method or not files_loc_list:
                    dfobj = details.get("dataflow", {})
                    dataflows = dfobj.get("list", [])
                    files_loc_list = set()
                    for df in dataflows:
                        location = df.get("location", {})
                        if location.get("file_name") == "N/A" or not location.get(
                            "line_number"
                        ):
                            continue
                        if not source_method:
                            source_method = f'{location.get("file_name")}:{location.get("line_number")}'
                        files_loc_list.add(
                            f'{location.get("file_name")}:{location.get("line_number")}'
                        )
                    if dataflows and dataflows[-1]:
                        sink = dataflows[-1].get("location", {})
                        if sink:
                            sink_method = (
                                f'{sink.get("file_name")}:{sink.get("line_number")}'
                            )
                if afinding.get("type") in (
                    "oss_vuln",
                    "container",
                    "extscan",
                    "secret",
                ):
                    reportwriter.writerow(
                        [
                            app_name,
                            app_group,
                            afinding.get("id"),
                            afinding.get("type"),
                            afinding.get("category"),
                            afinding.get("owasp_category"),
                            afinding.get("severity"),
                            "",
                            "",
                            afinding.get("title"),
                            afinding.get("version_first_seen"),
                            afinding.get("scan_first_seen"),
                            afinding.get("internal_id"),
                            cvss_31_severity_rating,
                            cvss_score,
                            reachability,
                            package_component,
                            cve,
                        ]
                    )
                elif afinding.get("type") in ("vuln"):
                    for loc in files_loc_list:
                        reportwriter.writerow(
                            [
                                app_name,
                                app_group,
                                afinding.get("id"),
                                afinding.get("type"),
                                afinding.get("category"),
                                afinding.get("owasp_category"),
                                afinding.get("severity"),
                                source_method,
                                sink_method,
                                loc,
                                afinding.get("version_first_seen"),
                                afinding.get("scan_first_seen"),
                                afinding.get("internal_id"),
                                cvss_31_severity_rating,
                                cvss_score,
                                "reachable"
                                if afinding.get("related_findings", [])
                                else "N/A",
                            ]
                        )


def get_all_findings(client, org_id, app_name, version):
    findings_list = []
    findings_url = get_findings_url(org_id, app_name, version, None)
    page_available = True
    scan = None
    counts = None
    while page_available:
        try:
            r = client.get(findings_url, headers=headers, timeout=config.timeout)
        except Exception:
            console.print(
                f"Unable to retrieve findings for {app_name} due to exception after {config.timeout} seconds"
            )
            page_available = False
            continue
        if r.status_code == 200:
            raw_response = r.json()
            if raw_response and raw_response.get("response"):
                response = raw_response.get("response")
                scan = response.get("scan")
                counts = response.get("counts")
                if not scan:
                    page_available = False
                    continue
                findings = response.get("findings")
                if not findings:
                    page_available = False
                    continue
                if os.getenv("TRIM_DESCRIPTION"):
                    for f in findings:
                        f["description"] = ""
                counts = response.get("counts")
                findings_list += findings
                if raw_response.get("next_page"):
                    parsed = urllib.parse.urlparse(raw_response.get("next_page"))
                    findings_url = parsed._replace(
                        netloc=config.SHIFTLEFT_API_HOST
                    ).geturl()
                else:
                    page_available = False
        else:
            page_available = False
            console.print(
                f"Unable to retrieve findings for {app_name} due to http error {r.status_code}"
            )
    return findings_list, scan, counts


def export_report(org_id, app_list, report_file, reports_dir, format):
    if not app_list:
        app_list = get_all_apps(org_id)
    findings_dict = {}
    work_dir = os.getcwd()
    for e in ["GITHUB_WORKSPACE", "WORKSPACE"]:
        if os.getenv(e):
            work_dir = os.getenv(e)
            break
    with Progress(
        transient=True,
        redirect_stderr=False,
        redirect_stdout=False,
        refresh_per_second=1,
    ) as progress:
        task = progress.add_task(
            f"[green] Export Findings for {len(app_list)} apps",
            total=len(app_list),
            start=True,
        )
        limits = httpx.Limits(
            max_keepalive_connections=20, max_connections=100, keepalive_expiry=120
        )
        with httpx.Client(http2="win32" not in sys.platform, limits=limits) as client:
            for app in app_list:
                app_id = app.get("id")
                app_name = app.get("name")
                progress.update(task, description=f"Processing [bold]{app_name}[/bold]")
                findings, scan, counts = get_all_findings(client, org_id, app_id, None)

                if format == "sarif":
                    app_sarif_file = report_file.replace(
                        ".sarif", "-" + app_id + ".sarif"
                    )
                    app_json_file = app_sarif_file.replace(".sarif", ".json")
                    with open(app_json_file, mode="w") as rp:
                        # Add findings to the JSON file
                        for afinding in findings:
                            tags = afinding.get("tags")
                            reachability = ""
                            package_component = ""
                            cve = ""
                            if tags:
                                for tag in tags:
                                    if tag.get("key") == "reachability":
                                        reachability = tag.get("value")
                                    elif tag.get("key") == "package_component":
                                        package_component = tag.get("value")
                                    elif tag.get("key") == "cve":
                                        cve = tag.get("value")
                            afinding["reachability"] = reachability
                            afinding["package_component"] = package_component
                            afinding["cve"] = cve

                        json.dump(
                            {app_name: findings},
                            rp,
                            ensure_ascii=True,
                            indent=None,
                        )
                        rp.flush()
                    convertLib.convert_file(
                        "ng-sast",
                        os.getenv("TOOL_VERSION"),
                        app_json_file,
                        app_sarif_file,
                    )
                    findings_dict[app_name] = {
                        "scan": scan,
                        "counts": counts,
                        "report_file": app_sarif_file,
                    }
                else:
                    export_csv([app], findings, report_file)
                progress.update(task, advance=1)
    return findings_dict


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ShiftLeft Findings Report Exporter")
    parser.add_argument(
        "-a",
        "--apps",
        help="Comma Separated list of apps to process. Leave empty for all apps.",
    )
    parser.add_argument(
        "-t", "--tags", help="Comma separated list of tags to filter apps"
    )
    parser.add_argument(
        "-d", "--outputdir", help="Output Directory for the reports", required=False
    )
    parser.add_argument(
        "-f",
        "--format",
        help="Output format",
        choices=["json", "xml", "csv", "sarif"],
        default="sarif",
    )
    args = parser.parse_args()

    config.SHIFTLEFT_API_TOKEN = os.getenv("SHIFTLEFT_API_TOKEN")
    org_id = extract_org_id(headers)

    report_file = os.getenv("GITHUB_STEP_SUMMARY", "/tmp/export_findings.sarif")
    if args.outputdir:
        report_file = os.path.join(args.outputdir, "export_findings.sarif")
        os.makedirs(args.outputdir, exist_ok=True)

    reports_dir = os.path.dirname(report_file)

    app_list = get_all_apps(org_id)
    export_report(org_id, app_list, report_file, reports_dir, args.format)
    end_time = time.monotonic_ns()
    total_time_sec = round((end_time - start_time) / 1000000000, 2)
