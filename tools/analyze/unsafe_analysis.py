#!/usr/bin/env python3
import argparse
import os
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

DEFAULT_RUSPE_PATH = REPO_ROOT
IGNORE_SUBSTRINGS = [
    "target",
    ".git",
    "tock",
    "musca",
    "test_nspe",
    "boards/psc3m5_evk/secure",
]


class RustCategory(str, Enum):
    UNSAFE_BLOCK = "Unsafe Block"
    INLINE_ASM = "Inline Assembly"
    UNSAFE_FN = "Unsafe Function"
    UNSAFE_ATTR = "Unsafe Attribute"
    UNSAFE_TRAIT_IMPL = "Unsafe Trait Implementation"
    UNSAFE_TRAIT_DECL = "Unsafe Trait Declaration"
    UNSAFE_EXTERN_BLOCK = "Unsafe Extern Block"
    OTHER = "Other"


class SystemCategory(str, Enum):
    ENTRY_POINTS = "Entry Points"
    IO_VECTORS = "IO-Vectors"
    EXCEPTION_HANDLING = "Exception Handling"
    HARDWARE_ACCESS = "Hardware Access"
    OPERATING_SYSTEM = "Operating System"


@dataclass
class ClassificationRule:
    category: SystemCategory
    path_contains: list[str] = field(default_factory=list)
    code_contains: list[str] = field(default_factory=list)

    def matches(self, path: str, code: str) -> bool:
        return any(p in path for p in self.path_contains) or any(
            c in code for c in self.code_contains
        )


SYSTEM_RULES: list[ClassificationRule] = [
    ClassificationRule(
        category=SystemCategory.EXCEPTION_HANDLING,
        path_contains=["faults.rs"],
        code_contains=["unhandled_interrupt"],
    ),
    ClassificationRule(
        category=SystemCategory.IO_VECTORS,
        code_contains=[
            "from_raw_parts",
            "svc_access_invec",
            "svc_access_outvec",
            "CtrlParam",
        ],
    ),
    ClassificationRule(
        category=SystemCategory.ENTRY_POINTS,
        path_contains=["startup.rs", "veneers.rs", "psa_veneer_client"],
        code_contains=[".vectors", ".irqs"],
    ),
    ClassificationRule(
        category=SystemCategory.HARDWARE_ACCESS,
        path_contains=[
            "cortex_m",
            "chips/",
            "static_ref.rs",
            "io.rs",
        ],
    ),
]


@dataclass(slots=True)
class Occurrence:
    rel_path: str
    line_num: int
    raw_code: str
    display_code: str
    rust_category: RustCategory
    system_category: SystemCategory
    loc_count: int = 0


@dataclass
class AnalysisResult:
    base_path: str
    total_files: int
    total_rust_loc: int
    occurrences: list[Occurrence]
    files_with_unsafe: set[str]

    @property
    def unsafe_blocks_loc(self) -> int:
        return sum(
            o.loc_count
            for o in self.occurrences
            if o.rust_category == RustCategory.UNSAFE_BLOCK
        )

    @property
    def asm_loc(self) -> int:
        return sum(
            o.loc_count
            for o in self.occurrences
            if o.rust_category == RustCategory.INLINE_ASM
        )

    @property
    def total_unsafe_loc(self) -> int:
        return self.unsafe_blocks_loc + self.asm_loc

    @property
    def safe_loc(self) -> int:
        return max(0, self.total_rust_loc - self.total_unsafe_loc)


def should_ignore(rel_path: str) -> bool:
    p = rel_path.replace("\\", "/")
    return any(ig in p for ig in IGNORE_SUBSTRINGS)


def clean_line(line: str) -> str:
    line = re.sub(r"//.*", "", line)
    line = re.sub(r"/\*.*?\*/", "", line)
    line = re.sub(r"'(?:\\.|[^\\'])*'", "''", line)
    return re.sub(r'".*?(?<!\\)"', '""', line)


def get_block_extent(
    lines: list[str], start_i: int, open_c: str = "{", close_c: str = "}"
) -> int:
    depth = 0
    started = False
    for i in range(start_i, len(lines)):
        for c in clean_line(lines[i]):
            if c == open_c:
                depth += 1
                started = True
            elif c == close_c:
                depth -= 1
                if started and depth <= 0:
                    return i
    return start_i


def classify_rust_construct(
    lines: list[str], idx: int, code_clean: str
) -> tuple[RustCategory | None, int]:
    if not re.search(r"\bunsafe\b", code_clean):
        return None, 0

    if "#[unsafe(naked)]" in code_clean or "naked" in code_clean:
        for i in range(idx, min(idx + 30, len(lines))):
            if "asm!(" in lines[i] or "global_asm!(" in lines[i]:
                asm_end = get_block_extent(lines, i, "(", ")")
                return RustCategory.INLINE_ASM, asm_end - i + 1

    if "{" in code_clean:
        end_idx = get_block_extent(lines, idx, "{", "}")
        for i in range(idx, end_idx + 1):
            if "asm!(" in lines[i] or "global_asm!(" in lines[i]:
                asm_end = get_block_extent(lines, i, "(", ")")
                return RustCategory.INLINE_ASM, asm_end - i + 1

    if "unsafe fn" in code_clean or "unsafe extern" in code_clean:
        return RustCategory.UNSAFE_FN, 0
    if "unsafe impl" in code_clean:
        return RustCategory.UNSAFE_TRAIT_IMPL, 0
    if "unsafe trait" in code_clean:
        return RustCategory.UNSAFE_TRAIT_DECL, 0

    if "extern" in code_clean and "fn" not in code_clean:
        return RustCategory.UNSAFE_EXTERN_BLOCK, 0
    if "#[unsafe" in code_clean:
        return RustCategory.UNSAFE_ATTR, 0

    end_idx = get_block_extent(lines, idx, "{", "}")
    return RustCategory.UNSAFE_BLOCK, end_idx - idx + 1


def classify_system_category(rel_path: str, code: str) -> SystemCategory:
    norm = rel_path.replace("\\", "/")
    for rule in SYSTEM_RULES:
        if rule.matches(norm, code):
            return rule.category
    return SystemCategory.OPERATING_SYSTEM


def run_analysis(ruspe_path: str) -> AnalysisResult:
    occurrences = []
    files_with_unsafe = set()
    total_rust_loc = 0
    total_files = 0

    for root, dirs, filenames in os.walk(ruspe_path):
        dirs[:] = [d for d in dirs if d not in ("target", ".git")]
        rel_dir = os.path.relpath(root, ruspe_path)
        for f in sorted(filenames):
            if not f.endswith(".rs"):
                continue
            rel_path = os.path.normpath(os.path.join(rel_dir, f))
            if should_ignore(rel_path):
                continue

            full_path = os.path.join(ruspe_path, rel_path)
            try:
                with open(full_path, "r", encoding="utf-8", errors="replace") as fp:
                    lines = fp.readlines()
            except OSError:
                continue

            total_files += 1
            total_rust_loc += len(lines)
            has_unsafe = False

            for idx, line in enumerate(lines):
                cleaned = clean_line(line).strip()
                rust_cat, count = classify_rust_construct(lines, idx, cleaned)
                if rust_cat is None:
                    continue

                sys_cat = classify_system_category(rel_path, line)
                disp = line.strip() + (f" [{count} lines]" if count > 0 else "")
                occurrences.append(
                    Occurrence(
                        rel_path=rel_path,
                        line_num=idx + 1,
                        raw_code=line.strip(),
                        display_code=disp,
                        rust_category=rust_cat,
                        system_category=sys_cat,
                        loc_count=count,
                    )
                )
                has_unsafe = True

            if has_unsafe:
                files_with_unsafe.add(rel_path)

    occurrences.sort(key=lambda o: (o.rel_path, o.line_num))
    return AnalysisResult(
        base_path=ruspe_path,
        total_files=total_files,
        total_rust_loc=total_rust_loc,
        occurrences=occurrences,
        files_with_unsafe=files_with_unsafe,
    )


def pct(num: int, den: int) -> str:
    return f"{(num / den * 100):.1f}%" if den > 0 else "0.0%"


def format_snippet_breakdown(items: list[Occurrence], link_prefix: str) -> list[str]:
    grouped = defaultdict(list)
    for occ in items:
        disp = (
            occ.display_code
            if len(occ.display_code) <= 80
            else occ.display_code[:77] + "..."
        )
        link = f"[{occ.rel_path}:{occ.line_num}]({link_prefix}/{occ.rel_path}#L{occ.line_num})"
        grouped[(disp, occ.rust_category.value)].append(link)

    lines = []
    for (code, cat), links in sorted(
        grouped.items(), key=lambda it: len(it[1]), reverse=True
    ):
        lines.append(f"- **`{code}`** — *{cat}* ({len(links)}x)")
        for link in links:
            lines.append(f"  - {link}")
    return lines


def generate_markdown_report(
    result: AnalysisResult, link_prefix: str = "../RuSPE"
) -> str:
    t_loc = result.total_rust_loc
    u_tot = result.total_unsafe_loc
    u_blocks = result.unsafe_blocks_loc
    asm_loc = result.asm_loc
    safe_loc = result.safe_loc
    files_with_unsafe_count = len(result.files_with_unsafe)

    lines = [
        "# Unsafe Code Analysis Report\n",
        "## Summary\n",
        f"- **Total Rust Files Analyzed:** {result.total_files}",
        f"- **Files containing `unsafe`:** {files_with_unsafe_count} ({pct(files_with_unsafe_count, result.total_files)})",
        f"- **Total `unsafe` Occurrences:** {len(result.occurrences)}",
    ]

    if t_loc > 0:
        lines.extend(
            [
                f"- **Total Rust LOC:** {t_loc}",
                f"- **Safe Rust LOC:** {safe_loc} ({pct(safe_loc, t_loc)} of total LOC)",
                f"- **Unsafe Blocks LOC:** {u_blocks} ({pct(u_blocks, u_tot)} of unsafe LOC, {pct(u_blocks, t_loc)} of total LOC)",
                f"- **Inline Assembly LOC:** {asm_loc} ({pct(asm_loc, u_tot)} of unsafe LOC, {pct(asm_loc, t_loc)} of total LOC)",
                f"- **Total Unsafe Logic LOC:** {u_tot} ({pct(u_tot, t_loc)} of total LOC)",
            ]
        )
    lines.append("")

    lines.extend(
        [
            "## System Categories Overview\n",
            "| System Category | Occurrences | Unsafe Blocks LOC | Inline ASM LOC | Total Unsafe LOC | % of Unsafe LOC | % of Total LOC |",
            "| :--- | :---: | :---: | :---: | :---: | :---: | :---: |",
        ]
    )

    sys_grouped = defaultdict(list)
    for occ in result.occurrences:
        sys_grouped[occ.system_category].append(occ)

    for sys_cat in SystemCategory:
        items = sys_grouped[sys_cat]
        b_loc = sum(
            it.loc_count
            for it in items
            if it.rust_category == RustCategory.UNSAFE_BLOCK
        )
        a_loc = sum(
            it.loc_count for it in items if it.rust_category == RustCategory.INLINE_ASM
        )
        tot = b_loc + a_loc
        lines.append(
            f"| **{sys_cat.value}** | {len(items)} | {b_loc} | {a_loc} | **{tot}** | {pct(tot, u_tot)} | {pct(tot, t_loc)} |"
        )
    lines.append("")

    lines.extend(
        [
            "## Rust Language Constructs Overview\n",
            "| Construct Category | Occurrences | LOC (Lines of Code) | % of Unsafe LOC | % of Total LOC |",
            "| :--- | :---: | :---: | :---: | :---: |",
        ]
    )

    rust_grouped = defaultdict(list)
    for occ in result.occurrences:
        rust_grouped[occ.rust_category].append(occ)

    for r_cat in sorted(RustCategory, key=lambda c: len(rust_grouped[c]), reverse=True):
        items = rust_grouped[r_cat]
        if not items:
            continue
        tot = sum(it.loc_count for it in items)
        loc_str = str(tot) if tot > 0 else "-"
        pct_u = pct(tot, u_tot) if tot > 0 else "-"
        pct_t = pct(tot, t_loc) if tot > 0 else "-"
        lines.append(
            f"| **{r_cat.value}** | {len(items)} | {loc_str} | {pct_u} | {pct_t} |"
        )
    lines.append("")

    lines.append("## Breakdown by System Category\n")
    for sys_cat in SystemCategory:
        items = sys_grouped[sys_cat]
        if not items:
            continue
        b_loc = sum(
            it.loc_count
            for it in items
            if it.rust_category == RustCategory.UNSAFE_BLOCK
        )
        a_loc = sum(
            it.loc_count for it in items if it.rust_category == RustCategory.INLINE_ASM
        )
        lines.append(
            f"### {sys_cat.value} ({len(items)} occurrences — {b_loc} LOC unsafe / {a_loc} LOC ASM ({b_loc + a_loc} LOC total))\n"
        )
        lines.extend(format_snippet_breakdown(items, link_prefix))
        lines.append("")

    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Analyze unsafe code usage in Rust codebase with system & construct categorizations."
    )
    parser.add_argument(
        "path", nargs="?", default=DEFAULT_RUSPE_PATH, help="Path to repository"
    )
    parser.add_argument("-o", "--output", help="Write report to file instead of stdout")
    parser.add_argument(
        "--link-prefix", default="../RuSPE", help="Path prefix for markdown links"
    )

    args = parser.parse_args()
    if not os.path.exists(args.path):
        sys.exit(f"Error: path '{args.path}' does not exist.")

    result = run_analysis(args.path)
    report = generate_markdown_report(result, link_prefix=args.link_prefix)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(report)
    else:
        print(report)


if __name__ == "__main__":
    main()
