#!/usr/bin/env python3

import argparse
import json
import math
from pathlib import Path
import subprocess
import sys
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parents[1]
TFM_ROOT = REPO_ROOT.parent / "trusted-firmware-m"
METRICS_TOOL = "rust-code-analysis-cli"

RUSPE_PATHS = (
    REPO_ROOT / "spe/spe_services/src/attest",
    REPO_ROOT / "libraries/cose",
)
TFM_PATHS = tuple(
    TFM_ROOT / path
    for path in (
        "lib/ext/t_cose-src/src/t_cose_crypto.h",
        "lib/ext/t_cose-src/src/t_cose_util.h",
        "lib/ext/t_cose-src/src/t_cose_sign1_sign.c",
        "lib/ext/t_cose-src/src/t_cose_util.c",
        "secure_fw/partitions/initial_attestation/attest.h",
        "secure_fw/partitions/initial_attestation/attest_asymmetric_key.c",
        "secure_fw/partitions/initial_attestation/attest_key.h",
        "secure_fw/partitions/initial_attestation/attest_token.h",
        "secure_fw/partitions/initial_attestation/tfm_attest.c",
        "secure_fw/partitions/initial_attestation/attest_token_encode.c",
        "secure_fw/partitions/initial_attestation/tfm_attest_req_mngr.c",
        "secure_fw/partitions/initial_attestation/attest_core.c",
    )
)


def metrics_command(paths: tuple[Path, ...], *excludes: str) -> list[str]:
    command = [METRICS_TOOL, "--metrics"]
    for path in paths:
        command.extend(("-p", str(path)))
    command.extend(("--output-format", "json"))
    for exclude in excludes:
        command.extend(("-X", exclude))
    return command


def run_metrics_command(command: list[str]) -> str:
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True,
            cwd=REPO_ROOT,
        )
        return result.stdout
    except FileNotFoundError:
        print(f"Could not find {METRICS_TOOL} on PATH.", file=sys.stderr)
        sys.exit(1)
    except subprocess.CalledProcessError as error:
        print(f"Metrics command failed: {error}", file=sys.stderr)
        if error.stderr:
            print(error.stderr, file=sys.stderr)
        sys.exit(1)


def parse_json_records(raw_json: str) -> list[dict[str, Any]]:
    content = raw_json.strip()
    if not content:
        return []

    try:
        data = json.loads(content)
        if isinstance(data, list):
            return [record for record in data if isinstance(record, dict)]
        elif isinstance(data, dict):
            return [data]
    except json.JSONDecodeError:
        pass

    records = []
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            pass

    return records


def extract_functions(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    functions = []

    def walk(space: dict[str, Any], file_path: str) -> None:
        if space.get("kind") == "function":
            metrics = space.get("metrics", {})
            cog = float(metrics.get("cognitive", {}).get("sum", 0.0))
            cyc = float(metrics.get("cyclomatic", {}).get("sum", 0.0))
            loc = metrics.get("loc", {})
            sloc = float(loc.get("sloc", 0.0))
            ploc = float(loc.get("ploc", 0.0))
            start_line = space.get("start_line", 0)
            end_line = space.get("end_line", 0)
            functions.append(
                {
                    "file": Path(file_path).name,
                    "full_path": file_path,
                    "name": space.get("name", "unnamed"),
                    "cognitive": cog,
                    "cyclomatic": cyc,
                    "sloc": sloc,
                    "ploc": ploc,
                    "lines": end_line - start_line + 1
                    if end_line and start_line
                    else sloc,
                }
            )
        for child in space.get("spaces", []):
            if isinstance(child, dict):
                walk(child, file_path)

    for r in records:
        fpath = r.get("name") or r.get("path", "unknown")
        walk(r, fpath)

    return functions


def average(values: list[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def analyze_project(
    name: str, command: list[str], top_percent: float = 10.0, top_n_longest: int = 5
) -> dict[str, Any] | None:
    raw_output = run_metrics_command(command)
    records = parse_json_records(raw_output)
    funcs = extract_functions(records)

    n = len(funcs)
    if n == 0:
        return None

    pct_fraction = top_percent / 100.0
    k = max(1, math.ceil(n * pct_fraction))
    rest_k = n - k

    # Overall metrics
    cogs = [f["cognitive"] for f in funcs]
    cycs = [f["cyclomatic"] for f in funcs]
    slocs = [f["sloc"] for f in funcs]
    plocs = [f["ploc"] for f in funcs]

    overall_cog_avg = average(cogs)
    overall_cyc_avg = average(cycs)
    overall_sloc_avg = average(slocs)

    total_sloc = sum(slocs)
    total_ploc = sum(plocs)

    sorted_by_cog = sorted(
        funcs,
        key=lambda x: (x["cognitive"], x["cyclomatic"], x["sloc"]),
        reverse=True,
    )
    top_cog_avg = average([f["cognitive"] for f in sorted_by_cog[:k]])
    rest_cog_avg = average([f["cognitive"] for f in sorted_by_cog[k:]])

    sorted_by_cyc = sorted(
        funcs,
        key=lambda x: (x["cyclomatic"], x["cognitive"], x["sloc"]),
        reverse=True,
    )
    top_cyc_avg = average([f["cyclomatic"] for f in sorted_by_cyc[:k]])
    rest_cyc_avg = average([f["cyclomatic"] for f in sorted_by_cyc[k:]])

    sorted_by_sloc = sorted(
        funcs,
        key=lambda x: (x["sloc"], x["ploc"], x["cyclomatic"]),
        reverse=True,
    )
    top_sloc = sorted_by_sloc[:k]
    rest_sloc = sorted_by_sloc[k:]

    top_sloc_sloc_avg = average([f["sloc"] for f in top_sloc])
    rest_sloc_sloc_avg = average([f["sloc"] for f in rest_sloc])

    top_sloc_cyc_avg = average([f["cyclomatic"] for f in top_sloc])
    rest_sloc_cyc_avg = average([f["cyclomatic"] for f in rest_sloc])

    top_sloc_cog_avg = average([f["cognitive"] for f in top_sloc])
    rest_sloc_cog_avg = average([f["cognitive"] for f in rest_sloc])

    top_5_longest = sorted_by_sloc[:top_n_longest]

    return {
        "name": name,
        "total_funcs": n,
        "k": k,
        "rest_k": rest_k,
        "top_percent": top_percent,
        "rest_percent": 100.0 - top_percent,
        "total_sloc": total_sloc,
        "total_ploc": total_ploc,
        "overall_cog_avg": overall_cog_avg,
        "overall_cyc_avg": overall_cyc_avg,
        "overall_sloc_avg": overall_sloc_avg,
        "top_cog_avg": top_cog_avg,
        "rest_cog_avg": rest_cog_avg,
        "top_cyc_avg": top_cyc_avg,
        "rest_cyc_avg": rest_cyc_avg,
        "top_sloc_sloc_avg": top_sloc_sloc_avg,
        "rest_sloc_sloc_avg": rest_sloc_sloc_avg,
        "top_sloc_cyc_avg": top_sloc_cyc_avg,
        "rest_sloc_cyc_avg": rest_sloc_cyc_avg,
        "top_sloc_cog_avg": top_sloc_cog_avg,
        "rest_sloc_cog_avg": rest_sloc_cog_avg,
        "top_5_longest": top_5_longest,
    }


def print_top_longest_functions(res: dict[str, Any], top_n: int = 5) -> None:
    print(f"\nTop {top_n} Longest Functions for {res['name']}:")
    print("-" * 90)
    header = f"{'Function Name':<35} | {'File Name':<25} | {'SLOC':>5} | {'PLOC':>5} | {'Cyclo':>6} | {'Cogn':>5}"
    print(header)
    print("-" * 90)
    for f in res["top_5_longest"]:
        print(
            f"{f['name']:<35} | {f['file']:<25} | {f['sloc']:>5.0f} | {f['ploc']:>5.0f} | {f['cyclomatic']:>6.0f} | {f['cognitive']:>5.0f}"
        )
    print()


def print_comparison_table(res1: dict[str, Any], res2: dict[str, Any]) -> None:
    pct = res1["top_percent"]
    rest_pct = res1["rest_percent"]

    print("\n" + "=" * 80)
    print("CODE COMPLEXITY COMPARISON SUMMARY")
    print("=" * 80)

    header = f"{'Metric Category':<45} | {res1['name']:>14} | {res2['name']:>14}"
    print(header)
    print("-" * len(header))

    print(
        f"{'Total Functions':<45} | {res1['total_funcs']:>14d} | {res2['total_funcs']:>14d}"
    )
    print(
        f"{'Total SLOC':<45} | {res1['total_sloc']:>14.0f} | {res2['total_sloc']:>14.0f}"
    )
    print(
        f"{'Total PLOC':<45} | {res1['total_ploc']:>14.0f} | {res2['total_ploc']:>14.0f}"
    )
    print(
        f"{'Overall Avg Cognitive Complexity':<45} | {res1['overall_cog_avg']:>14.2f} | {res2['overall_cog_avg']:>14.2f}"
    )
    print(
        f"{'Overall Avg Cyclomatic Complexity':<45} | {res1['overall_cyc_avg']:>14.2f} | {res2['overall_cyc_avg']:>14.2f}"
    )
    print(
        f"{'Overall Avg SLOC':<45} | {res1['overall_sloc_avg']:>14.2f} | {res2['overall_sloc_avg']:>14.2f}"
    )

    print("-" * len(header))
    print(
        f"{f'Top {pct:.0f}% Highest Cognitive - Avg':<45} | {res1['top_cog_avg']:>14.2f} | {res2['top_cog_avg']:>14.2f}"
    )
    print(
        f"{f'Rest {rest_pct:.0f}% Highest Cognitive - Avg':<45} | {res1['rest_cog_avg']:>14.2f} | {res2['rest_cog_avg']:>14.2f}"
    )

    print("-" * len(header))
    print(
        f"{f'Top {pct:.0f}% Highest Cyclomatic - Avg':<45} | {res1['top_cyc_avg']:>14.2f} | {res2['top_cyc_avg']:>14.2f}"
    )
    print(
        f"{f'Rest {rest_pct:.0f}% Highest Cyclomatic - Avg':<45} | {res1['rest_cyc_avg']:>14.2f} | {res2['rest_cyc_avg']:>14.2f}"
    )

    print("-" * len(header))
    print(
        f"{f'Top {pct:.0f}% Longest - SLOC Avg':<45} | {res1['top_sloc_sloc_avg']:>14.2f} | {res2['top_sloc_sloc_avg']:>14.2f}"
    )
    print(
        f"{f'Rest {rest_pct:.0f}% Longest - SLOC Avg':<45} | {res1['rest_sloc_sloc_avg']:>14.2f} | {res2['rest_sloc_sloc_avg']:>14.2f}"
    )
    print(
        f"{f'Top {pct:.0f}% Longest - Cyclo Avg':<45} | {res1['top_sloc_cyc_avg']:>14.2f} | {res2['top_sloc_cyc_avg']:>14.2f}"
    )
    print(
        f"{f'Rest {rest_pct:.0f}% Longest - Cyclo Avg':<45} | {res1['rest_sloc_cyc_avg']:>14.2f} | {res2['rest_sloc_cyc_avg']:>14.2f}"
    )
    print(
        f"{f'Top {pct:.0f}% Longest - Cogn Avg':<45} | {res1['top_sloc_cog_avg']:>14.2f} | {res2['top_sloc_cog_avg']:>14.2f}"
    )
    print(
        f"{f'Rest {rest_pct:.0f}% Longest - Cogn Avg':<45} | {res1['rest_sloc_cog_avg']:>14.2f} | {res2['rest_sloc_cog_avg']:>14.2f}"
    )
    print("=" * 80 + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Calculate code metrics (Cognitive, Cyclomatic, SLOC) for RuSPE and TF-M."
    )
    parser.add_argument(
        "--top-percent",
        type=float,
        default=10.0,
        help="Percentage for top percentile calculations (default: 10.0)",
    )
    args = parser.parse_args()
    if not 0 < args.top_percent <= 100:
        parser.error("--top-percent must be greater than 0 and at most 100")

    ruspe_res = analyze_project(
        "RuSPE (Rust)",
        metrics_command(RUSPE_PATHS, "*_test.rs", "mod.rs"),
        top_percent=args.top_percent,
    )
    tfm_res = analyze_project(
        "TF-M (C)", metrics_command(TFM_PATHS), top_percent=args.top_percent
    )

    if not ruspe_res or not tfm_res:
        print("Error: Could not retrieve metric records.", file=sys.stderr)
        sys.exit(1)

    print_top_longest_functions(ruspe_res, top_n=5)
    print_top_longest_functions(tfm_res, top_n=5)
    print_comparison_table(ruspe_res, tfm_res)


if __name__ == "__main__":
    main()
