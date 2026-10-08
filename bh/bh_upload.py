#!/usr/bin/env python3
"""Ingest PrivHound JSON and register custom node icons or saved queries in BloodHound."""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import glob
import hashlib
import hmac
import io
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path


def load_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        match = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\s*[:=]\s*(.*)$", line)
        if not match:
            raise ValueError(f"Invalid environment entry on line {number}; expected KEY=VALUE.")
        key, value = match.groups()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        values[key.upper()] = value
    return values


def api_signature(key: str, method: str, request_uri: str, date: str, body: bytes) -> str:
    """Create BloodHound API HMAC chain signature."""
    digest = hmac.new(key.encode("utf-8"), (method + request_uri).encode("utf-8"), hashlib.sha256).digest()
    digest = hmac.new(digest, date[:13].encode("utf-8"), hashlib.sha256).digest()
    digest = hmac.new(digest, body, hashlib.sha256).digest()
    return base64.b64encode(digest).decode("ascii")


def request_api(
    base_url: str,
    config: dict[str, str],
    method: str,
    path: str,
    body: bytes | None = None,
    extra_headers: dict[str, str] | None = None,
):
    token = config.get("BH_TOKEN", "")
    key, token_id = config.get("BH_KEY", ""), config.get("BH_ID", "")
    if not token and (not key or not token_id):
        raise ValueError("Configure BH_TOKEN or both BH_KEY and BH_ID in the .env file.")

    headers = dict(extra_headers or {})
    request_date = dt.datetime.now().astimezone().isoformat(timespec="milliseconds")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    else:
        headers.update(
            {
                "Authorization": f"bhesignature {token_id}",
                "RequestDate": request_date,
                "Signature": api_signature(key, method, path, request_date, body or b""),
            }
        )
    req = urllib.request.Request(base_url.rstrip("/") + path, data=body, headers=headers, method=method)
    for attempt in range(8):
        try:
            with urllib.request.urlopen(req, timeout=120) as response:
                content = response.read()
                return json.loads(content) if content else None
        except urllib.error.HTTPError as exc:
            if exc.code != 429 or attempt == 7:
                raise
            retry_after = exc.headers.get("Retry-After")
            try:
                delay = max(1.0, float(retry_after)) if retry_after else min(2**attempt, 60)
            except ValueError:
                delay = min(2**attempt, 60)
            exc.close()
            print(f"BloodHound rate limit reached; retrying in {delay:g}s.", file=sys.stderr)
            time.sleep(delay)


def upload_graph(name: str, graph_bytes: bytes, base_url: str, config: dict[str, str]) -> None:
    try:
        # BloodHound's file-ingest API uses a job lifecycle, not multipart POST.
        started = request_api(base_url, config, "POST", "/api/v2/file-upload/start")
        job = started.get("data", started) if isinstance(started, dict) else {}
        job_id = job.get("id")
        if job_id is None:
            raise RuntimeError(f"BloodHound did not return an upload job ID: {started}")
        request_api(
            base_url,
            config,
            "POST",
            f"/api/v2/file-upload/{job_id}",
            graph_bytes,
            {"Content-Type": "application/json", "X-File-Upload-Name": name},
        )
        request_api(base_url, config, "POST", f"/api/v2/file-upload/{job_id}/end")
        print(f"Uploaded {name} successfully (job {job_id}).")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Upload failed for {name} (HTTP {exc.code}): {detail}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Could not reach BloodHound for {name}: {exc.reason}") from exc


def upload(file_path: Path, base_url: str, config: dict[str, str]) -> None:
    if file_path.suffix.lower() != ".zip":
        upload_graph(file_path.name, file_path.read_bytes(), base_url, config)
        return

    # Upload each OpenGraph JSON individually; the file-ingest endpoint expects
    # graph data, whereas a ZIP can also contain custom-node definitions.
    with zipfile.ZipFile(file_path) as archive:
        graph_count = 0
        for entry in archive.infolist():
            if entry.is_dir() or not entry.filename.lower().endswith(".json"):
                continue
            name = Path(entry.filename).name
            graph_bytes = archive.read(entry)
            try:
                payload = json.loads(graph_bytes)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ValueError(f"Invalid JSON in {file_path.name}: {entry.filename}: {exc}") from exc
            graph = payload.get("graph") if isinstance(payload, dict) else None
            if not isinstance(graph, dict) or not isinstance(graph.get("nodes"), list) or not isinstance(graph.get("edges"), list):
                print(f"Skipping non-OpenGraph JSON in {file_path.name}: {entry.filename}")
                continue
            upload_graph(name, graph_bytes, base_url, config)
            graph_count += 1
        if not graph_count:
            raise ValueError(f"No OpenGraph JSON files found in {file_path}.")


def register_custom_nodes(json_path: Path, base_url: str, config: dict[str, str]) -> None:
    try:
        body = json_path.read_bytes()
        payload = json.loads(body)
        custom_types = payload.get("custom_types", {})
        if not isinstance(custom_types, dict) or not custom_types:
            raise ValueError(f"No custom_types found in {json_path}.")

        api_path = "/api/v2/custom-nodes"
        response = request_api(base_url, config, "GET", api_path)
        existing = response.get("data", []) if isinstance(response, dict) else []
        names = {
            item.get("kindName") for item in existing
            if isinstance(item, dict) and item.get("kindName")
        }
        new_types = {}
        updated_count = 0
        for name, custom_config in custom_types.items():
            if name not in names:
                new_types[name] = custom_config
                continue
            encoded_name = urllib.parse.quote(name, safe="")
            update_body = json.dumps({"config": custom_config}).encode("utf-8")
            request_api(
                base_url,
                config,
                "PUT",
                f"{api_path}/{encoded_name}",
                update_body,
                {"Content-Type": "application/json"},
            )
            updated_count += 1

        if new_types:
            create_body = json.dumps({"custom_types": new_types}).encode("utf-8")
            request_api(
                base_url,
                config,
                "POST",
                api_path,
                create_body,
                {"Content-Type": "application/json"},
            )
        print(
            f"Registered {len(new_types)} new and updated {updated_count} existing "
            f"custom node types from {json_path.name}."
        )
        print("Hard-refresh BloodHound (Ctrl+Shift+R) to see the icons.")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Custom-node registration failed (HTTP {exc.code}): {detail}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Could not reach BloodHound: {exc.reason}") from exc


def parse_cypher_queries(cypher_text: str) -> list[dict[str, str]]:
    queries: list[dict[str, str]] = []
    title: str | None = None
    details: list[str] = []
    query_lines: list[str] = []
    used_names: set[str] = set()

    def finish_query() -> None:
        nonlocal title, details, query_lines
        query = "\n".join(query_lines).strip()
        if query:
            label = title or f"PrivHound query {len(queries) + 1}"
            base_name = label.replace("_", " ")
            name = base_name
            suffix = 2
            while name in used_names:
                name = f"{base_name} ({suffix})"
                suffix += 1
            used_names.add(name)
            description = ". ".join([label, *details])
            queries.append({"name": name, "query": query, "description": description})
        title, details, query_lines = None, [], []

    for line in cypher_text.splitlines():
        stripped = line.strip()
        if stripped.startswith("##"):
            if query_lines:
                finish_query()
            heading = stripped[2:].strip()
            if title is None:
                title = heading
            else:
                details.append(heading)
        elif not stripped:
            if query_lines:
                finish_query()
        elif stripped.startswith("#"):
            continue
        else:
            query_lines.append(line.rstrip())
    finish_query()
    return queries


LEGACY_QUERY_NAMES = {
    "cmdkey entries (runas reuse unverified)": "cmdkey → runas /savecred → local user → admin",
    "SCCM credential-source observations (credentials unverified)": "SCCM NAA → credential pipeline → admin",
    "List SCCM credential-source nodes": "SCCM NAA → login → admin (full chain)",
}


def register_queries(cypher_path: Path, base_url: str, config: dict[str, str]) -> None:
    queries = parse_cypher_queries(cypher_path.read_text(encoding="utf-8"))
    if not queries:
        raise ValueError(f"No Cypher queries found in {cypher_path}.")

    try:
        api_path = "/api/v2/saved-queries"
        response = request_api(base_url, config, "GET", api_path)
        existing = response.get("data", []) if isinstance(response, dict) else []
        available = [item for item in existing if isinstance(item, dict)]
        unchanged_count = 0
        updated_count = 0
        new_queries = []

        for query in queries:
            # Match by name first: editing the query text must update the saved
            # query rather than import a second copy of it.
            previous_name = LEGACY_QUERY_NAMES.get(query["name"])
            matching_index = next(
                (
                    index
                    for index, saved in enumerate(available)
                    if saved.get("name") == query["name"]
                ),
                None,
            )
            if matching_index is None and previous_name:
                matching_index = next(
                    (index for index, saved in enumerate(available)
                     if saved.get("name") == previous_name),
                    None,
                )
            if matching_index is None:
                matching_index = next(
                    (index for index, saved in enumerate(available)
                     if saved.get("query", "").strip() == query["query"].strip()),
                    None,
                )
            if matching_index is None:
                new_queries.append(query)
                continue

            saved = available.pop(matching_index)
            if all(saved.get(field, "").strip() == query[field].strip()
                   for field in ("name", "description", "query")):
                unchanged_count += 1
                continue
            query_id = saved.get("id")
            if query_id is None:
                raise RuntimeError(f"Saved query has no ID and cannot be renamed: {saved.get('name')}")
            body = json.dumps(query, ensure_ascii=False).encode("utf-8")
            request_api(base_url, config, "PUT", f"{api_path}/{query_id}", body, {"Content-Type": "application/json"})
            updated_count += 1

        if new_queries:
            archive = io.BytesIO()
            with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
                for index, query in enumerate(new_queries, 1):
                    filename = f"privhound_query_{index:02d}.json"
                    bundle.writestr(filename, json.dumps(query, ensure_ascii=False))
            request_api(
                base_url,
                config,
                "POST",
                f"{api_path}/import",
                archive.getvalue(),
                {"Content-Type": "application/zip"},
            )
        print(
            f"Saved queries from {cypher_path.name}: {updated_count} renamed/updated, "
            f"{unchanged_count} unchanged, {len(new_queries)} imported."
        )
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Saved-query registration failed (HTTP {exc.code}): {detail}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Could not reach BloodHound: {exc.reason}") from exc


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument(
        "-ingest", "--ingest", action="store_true", help="ingest OpenGraph JSON or ZIP (the default)"
    )
    modes.add_argument(
        "-register-node",
        "--register-node",
        nargs="?",
        const="privhound_customnodes.json",
        metavar="JSON_FILE",
        help="register custom node types from JSON_FILE (default: privhound_customnodes.json)",
    )
    modes.add_argument(
        "-register-query",
        "--register-query",
        nargs="?",
        const=str(Path(__file__).resolve().parent / "privhound_queries.cypher"),
        metavar="CYPHER_FILE",
        help="import saved queries from CYPHER_FILE (default: bundled query file)",
    )
    parser.add_argument("paths", nargs="*", help="OpenGraph JSON/ZIP files or wildcard patterns")
    parser.add_argument(
        "--env",
        type=Path,
        default=Path(__file__).resolve().parent.parent / ".env",
        help="dotenv path (default: project-root .env)",
    )
    args = parser.parse_args()

    try:
        config = load_env(args.env)
        base_url = config.get("BH_URL") or config.get("URL")
        if not base_url:
            raise ValueError("BH_URL (or url) is missing from the environment file.")
        if not config.get("BH_TOKEN") and not (config.get("BH_KEY") or config.get("KEY")):
            raise ValueError("Configure BH_TOKEN or the API key/ID pair in the environment file.")
        if not config.get("BH_ID"):
            config["BH_ID"] = config.get("ID", "")
        if not config.get("BH_KEY"):
            config["BH_KEY"] = config.get("KEY", "")

        if args.register_node is not None:
            if args.paths:
                raise ValueError("Pass the custom-node JSON directly after --register-node.")
            node_file = Path(args.register_node)
            if not node_file.is_file():
                raise ValueError(f"Custom-node definition file not found: {node_file}")
            register_custom_nodes(node_file, base_url, config)
        elif args.register_query is not None:
            if args.paths:
                raise ValueError("Pass the Cypher file directly after --register-query.")
            cypher_file = Path(args.register_query)
            if not cypher_file.is_file():
                raise ValueError(f"Cypher query file not found: {cypher_file}")
            register_queries(cypher_file, base_url, config)
        else:
            if not args.paths:
                raise ValueError("Provide one or more JSON or ZIP files to ingest.")
            files = sorted(
                {
                    Path(match).resolve()
                    for pattern in args.paths
                    for match in glob.glob(pattern)
                    if Path(match).is_file()
                }
            )
            if not files:
                raise ValueError("No input files found for the supplied path(s).")
            for file_path in files:
                print(f"Uploading graphs from {file_path.name} to {base_url.rstrip('/')}/api/v2/file-upload ...")
                upload(file_path, base_url, config)
    except (OSError, ValueError, RuntimeError, zipfile.BadZipFile) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
