import sys
from intelhex import IntelHex


def normalize_tzm(addr: int) -> int:
    """Maps Non-Secure Aliases (0x22xxxxxx) to Secure Aliases (0x32xxxxxx) for contiguous gap tracking."""
    if (addr >> 24) == 0x22:
        return addr | 0x10000000
    return addr


def get_memory_map_report(hex_file_path: str) -> str:
    try:
        ih = IntelHex(hex_file_path)
    except Exception as e:
        return f"Error loading HEX file: {e}"

    raw_segments = sorted(ih.segments())
    if not raw_segments:
        return "File contains no data segments."

    lines = [
        f"=== MEMORY MAP: {hex_file_path} ===",
        f" {'Start Address':<14} | {'End Address':<14} | {'Size (Bytes)':<12} | {'Size (KB)':<10}",
        "-" * 62,
    ]

    total_used = 0
    # Store a mapping of normalized addresses back to their original addresses
    # Format: (norm_start, norm_end, orig_start, orig_end)
    segments_meta = []

    # 1. Print Used Segments & Populate Meta Array
    for start, end in raw_segments:
        size = end - start
        total_used += size
        lines.append(
            f" {hex(start):<14} | {hex(end - 1):<14} | {size:<12,} | {size / 1024:<10.2f}"
        )
        segments_meta.append((normalize_tzm(start), normalize_tzm(end), start, end))

    # Sort primarily by normalized start addresses
    segments_meta.sort(key=lambda x: x[0])

    # 2. Calculate and Display Gaps using Original Addresses
    lines.append("\n[ INTERNAL GAPS ]")
    total_gap = 0
    gap_lines = []

    for i in range(len(segments_meta) - 1):
        norm_gap_start = segments_meta[i][1]
        norm_gap_end = segments_meta[i + 1][0]

        if norm_gap_end > norm_gap_start:
            size = norm_gap_end - norm_gap_start
            total_gap += size

            # Recover original addressing context
            # We add the normalized delta back to the previous block's actual base
            orig_prev_end = segments_meta[i][3]
            orig_next_start = segments_meta[i + 1][2]

            gap_lines.append(
                f" {hex(orig_prev_end):<14} | {hex(orig_next_start - 1):<14} | {size:<12,} | {size / 1024:<10.2f}"
            )

    if gap_lines:
        lines.extend(gap_lines)
    else:
        lines.append(" No internal gaps detected (continuous memory spaces).")

    # 3. Summary Statistics
    low_norm = segments_meta[0][0]
    high_norm = segments_meta[-1][1] - 1
    span = high_norm - low_norm + 1

    lines.extend(
        [
            "\n=== SUMMARY (NORMALIZED) ===",
            f" Lowest Address:    {hex(raw_segments[0][0])}",
            f" Highest Address:   {hex(raw_segments[-1][1] - 1)}",
            f" Total Memory Span: {span:,} bytes ({span / 1024:.2f} KB)",
            f" Actual Data Size:  {total_used:,} bytes ({total_used / 1024:.2f} KB)",
            f" Internal Gap Size: {total_gap:,} bytes ({total_gap / 1024:.2f} KB)",
            "============================",
        ]
    )

    return "\n".join(lines)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python script.py <filename.hex>")
        sys.exit(1)

    print(get_memory_map_report(sys.argv[1]))
