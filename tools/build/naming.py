# SPDX-FileCopyrightText: Infineon Technologies AG
#
# SPDX-License-Identifier: MIT

"""Naming constants and filename builders for build artifacts."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Union

if TYPE_CHECKING:
    from tools.build.board import BoardConfig

# ── Filename suffixes ────────────────────────────────────────────
SUFFIX_APPS_ELF = "+apps.elf"
SUFFIX_NOAPPS_BIN = "_noapps.bin"
SUFFIX_COMBINED_TOCK_APPS = "_combined_tock_apps.tbf"
SUFFIX_HEX = ".hex"


# ── Internal helpers ─────────────────────────────────────────────


def _crate_name(board: Union[BoardConfig, str]) -> str:
    """Resolve a BoardConfig or plain string to its crate name."""
    if hasattr(board, "crate_name"):
        return str(board.crate_name)
    return str(board)


def _board_name(board: Union[BoardConfig, str]) -> str:
    """Resolve a BoardConfig or plain string to its board name."""
    if hasattr(board, "board_name"):
        return str(board.board_name)
    name = str(board)
    if "psc3" in name:
        return "psc3m5_evk"
    if "musca" in name:
        return "musca_b1"
    return name.split("_")[0]


def _nspe_suffix(
    secure: Union[BoardConfig, str], non_secure: Union[BoardConfig, str]
) -> str:
    """Strip the board prefix and +apps tail from the non-secure crate name."""
    ns_crate = _crate_name(non_secure)
    prefix = f"{_board_name(secure)}_"
    if ns_crate.startswith(prefix):
        ns_crate = ns_crate[len(prefix) :]
    if ns_crate.endswith("+apps"):
        ns_crate = ns_crate[:-5]
    return ns_crate


# ── Merged hex filename builder ──────────────────────────────────


@dataclass(frozen=True)
class MergedArtifactName:
    """Describes a merged SPE+NSPE hex artifact for filename derivation.

    Construct with the secure and non-secure board identifiers plus
    the boolean traits of the artifact.  The filename is computed
    lazily via the ``hex`` property.
    """

    secure: Union[BoardConfig, str]
    non_secure: Union[BoardConfig, str]
    has_apps: bool = False
    has_services: bool = False

    @property
    def hex(self) -> str:
        """The merged .hex filename, e.g. ``psc3m5_evk_secure_ipc+services+test_nspe.hex``."""
        spe = _crate_name(self.secure)
        nspe = _nspe_suffix(self.secure, self.non_secure)
        services = "+services" if self.has_services else ""
        apps = "+apps" if self.has_apps else ""
        return f"{spe}{services}+{nspe}{apps}{SUFFIX_HEX}"

    # ── Convenience constructors ─────────────────────────────────

    @classmethod
    def tock(
        cls,
        secure: Union[BoardConfig, str],
        non_secure: Union[BoardConfig, str],
    ) -> MergedArtifactName:
        """Tock kernel merged hex (always has apps)."""
        return cls(secure=secure, non_secure=non_secure, has_apps=True)

    @classmethod
    def ipc(
        cls,
        secure: Union[BoardConfig, str],
        non_secure: Union[BoardConfig, str],
        has_apps: bool = False,
    ) -> MergedArtifactName:
        """IPC merged hex (always has services)."""
        return cls(
            secure=secure,
            non_secure=non_secure,
            has_apps=has_apps,
            has_services=True,
        )


# ── Single-crate filename helpers ────────────────────────────────


def app_elf_filename(board: Union[BoardConfig, str]) -> str:
    """Kernel ELF with injected apps, e.g. ``musca_b1_tock_kernel+apps.elf``."""
    return f"{_crate_name(board)}{SUFFIX_APPS_ELF}"


def noapps_bin_filename(board: Union[BoardConfig, str]) -> str:
    """Kernel binary without apps, e.g. ``musca_b1_tock_kernel_noapps.bin``."""
    return f"{_crate_name(board)}{SUFFIX_NOAPPS_BIN}"


def combined_tock_apps_filename(board: str) -> str:
    """Combined TBF bundle, e.g. ``musca_b1_combined_tock_apps.tbf``."""
    return f"{board}{SUFFIX_COMBINED_TOCK_APPS}"


def psa_app_crate_name(board: str) -> str:
    """PSA API userland application crate name, e.g. ``musca_b1_tock_psa_app``."""
    return f"{board}_tock_psa_app"
