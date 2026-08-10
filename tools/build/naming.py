# SPDX-FileCopyrightText: Infineon Technologies AG
#
# SPDX-License-Identifier: MIT

"""Naming constants and path/filename constructor functions for build artifacts."""

from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    pass

SUFFIX_APPS_ELF = "+apps.elf"
SUFFIX_NOAPPS_BIN = "_noapps.bin"
SUFFIX_COMBINED_TOCK_APPS = "_combined_tock_apps.tbf"
SUFFIX_HEX = ".hex"


def get_crate_name(board_or_crate: Any) -> str:
    """Return crate_name if passed a BoardConfig or the string itself if passed a str."""
    if hasattr(board_or_crate, "crate_name"):
        return str(board_or_crate.crate_name)
    return str(board_or_crate)


def get_board_name(board_or_crate: Any) -> str:
    """Return board_name if passed a BoardConfig or infer it from crate string."""
    if hasattr(board_or_crate, "board_name"):
        return str(board_or_crate.board_name)
    name = str(board_or_crate)
    if "psc3" in name:
        return "psc3m5_evk"
    elif "musca" in name:
        return "musca_b1"
    return name.split("_")[0]


def _extract_nspe_suffix(secure_board: Any, non_secure_board: Any) -> tuple[str, str]:
    """Helper to extract secure crate name and board-stripped NSPE suffix."""
    secure_crate = get_crate_name(secure_board)
    non_secure_crate = get_crate_name(non_secure_board)
    board_name = get_board_name(secure_board)

    board_prefix = f"{board_name}_"
    nspe_suffix = non_secure_crate
    if nspe_suffix.startswith(board_prefix):
        nspe_suffix = nspe_suffix[len(board_prefix) :]

    if nspe_suffix.endswith("+apps"):
        nspe_suffix = nspe_suffix[:-5]

    return secure_crate, nspe_suffix


def get_merged_hex_filename(
    secure_board: Any,
    non_secure_board: Any,
    has_apps: bool = False,
    has_services: bool = False,
) -> str:
    """Construct the merged HEX filename using '+' to join SPE, services (if present), and NSPE (and +apps if present).

    Example: get_merged_hex_filename("musca_b1_secure", "musca_b1_test_nspe") -> "musca_b1_secure+test_nspe.hex"
    """
    secure_crate, nspe_suffix = _extract_nspe_suffix(secure_board, non_secure_board)
    services_part = "+services" if has_services else ""
    apps_part = "+apps" if has_apps else ""
    return f"{secure_crate}{services_part}+{nspe_suffix}{apps_part}{SUFFIX_HEX}"


def get_merged_tock_hex_filename(secure_board: Any, non_secure_board: Any) -> str:
    """Construct the merged HEX filename for Tock kernel with embedded apps.

    Example: get_merged_tock_hex_filename("musca_b1_secure", "musca_b1_tock_kernel") -> "musca_b1_secure+tock_kernel+apps.hex"
    """
    return get_merged_hex_filename(secure_board, non_secure_board, has_apps=True)


def get_merged_ipc_hex_filename(
    secure_board: Any, non_secure_board: Any, has_apps: bool = False
) -> str:
    """Construct the merged HEX filename for Secure IPC with services.

    Example: get_merged_ipc_hex_filename("psc3m5_evk_secure_ipc", "psc3m5_evk_test_nspe") -> "psc3m5_evk_secure_ipc+services+test_nspe.hex"
    """
    return get_merged_hex_filename(
        secure_board, non_secure_board, has_apps=has_apps, has_services=True
    )


def get_app_elf_filename(board_or_crate: Any) -> str:
    """Construct the kernel app-injected ELF filename.

    Example: get_app_elf_filename("musca_b1_tock_kernel") -> "musca_b1_tock_kernel+apps.elf"
    """
    return f"{get_crate_name(board_or_crate)}{SUFFIX_APPS_ELF}"


def get_noapps_bin_filename(board_or_crate: Any) -> str:
    """Construct the kernel no-apps BIN filename.

    Example: get_noapps_bin_filename("musca_b1_tock_kernel") -> "musca_b1_tock_kernel_noapps.bin"
    """
    return f"{get_crate_name(board_or_crate)}{SUFFIX_NOAPPS_BIN}"


def get_combined_tock_apps_filename(board: str) -> str:
    """Construct the combined Tock apps TBF filename for a board.

    Example: get_combined_tock_apps_filename("musca_b1") -> "musca_b1_combined_tock_apps.tbf"
    """
    return f"{board}{SUFFIX_COMBINED_TOCK_APPS}"


def get_psa_app_filename(board: str) -> str:
    """Construct the PSA API userland application name for a board.

    Example: get_psa_app_filename("musca_b1") -> "musca_b1_tock_psa_app"
    """
    return f"{board}_tock_psa_app"
