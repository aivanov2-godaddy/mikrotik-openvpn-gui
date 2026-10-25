"""Validate project image identities used by the guarded release workflow."""

from __future__ import annotations

from dataclasses import dataclass
import re


PROJECT_PATH = "aivanov2-godaddy/mikrotik-openvpn-gui"
PROJECT_REPOSITORY = f"ghcr.io/{PROJECT_PATH}"
SHA256_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
REVISION = re.compile(r"^[0-9a-f]{40}$")
_IMAGE = re.compile(
    r"^(?:ghcr\.io/)?aivanov2-godaddy/mikrotik-openvpn-gui:"
    r"sha-(?P<revision>[0-9a-f]{40})-(?P<architecture>arm64|amd64)"
    r"(?:@(?P<digest>sha256:[0-9a-f]{64}))?$"
)


@dataclass(frozen=True, slots=True)
class ImageIdentity:
    revision: str
    architecture: str
    digest: str | None


def parse_project_image(value: str, *, require_digest: bool = True, architecture: str | None = None) -> ImageIdentity:
    """Parse a project commit tag, optionally digest-pinned, fail-closed."""

    match = _IMAGE.fullmatch(value)
    if match is None:
        raise ValueError("image must be this project's full architecture-specific SHA reference")
    image_architecture = match.group("architecture")
    digest = match.group("digest")
    if require_digest and digest is None:
        raise ValueError("image reference must include its SHA-256 digest")
    if architecture is not None and image_architecture != architecture:
        raise ValueError("image architecture does not match the requested platform")
    return ImageIdentity(match.group("revision"), image_architecture, digest)


def registry_relative_image(value: str) -> str:
    """Normalize a validated project image for RouterOS registry-url usage."""

    identity = parse_project_image(value, require_digest=False)
    digest_suffix = f"@{identity.digest}" if identity.digest is not None else ""
    return f"{PROJECT_PATH}:sha-{identity.revision}-{identity.architecture}{digest_suffix}"


def pin_project_image(value: str, digest: str) -> str:
    """Return the canonical full reference for a tag and its verified digest."""

    identity = parse_project_image(value, require_digest=False)
    if not SHA256_DIGEST.fullmatch(digest):
        raise ValueError("digest must be a lowercase SHA-256 OCI digest")
    if identity.digest is not None and identity.digest != digest:
        raise ValueError("image reference and supplied digest do not match")
    return (
        f"{PROJECT_REPOSITORY}:sha-{identity.revision}-{identity.architecture}"
        f"@{digest}"
    )


def image_digest(value: str) -> str:
    """Return the immutable digest embedded in an image reference."""

    identity = parse_project_image(value, require_digest=True)
    assert identity.digest is not None
    return identity.digest
