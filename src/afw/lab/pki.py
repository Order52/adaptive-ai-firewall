"""Lab-only PKI (openssl CLI): one CA, leaf certificates with IP SANs.

Material lives in ``~/.config/afw/pki`` (outside Git) and is copied to guests
by the provisioning steps. Nothing here is suitable for production use.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

PKI_DIR = Path("~/.config/afw/pki").expanduser()
OPENSSL = "/usr/bin/openssl"


def _run(*args: str) -> None:
    subprocess.run([OPENSSL, *args], check=True, capture_output=True)  # noqa: S603


def ensure_ca(d: Path = PKI_DIR) -> Path:
    d.mkdir(parents=True, exist_ok=True, mode=0o700)
    key, crt = d / "lab-ca.key", d / "lab-ca.pem"
    if not crt.exists():
        _run(
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-nodes",
            "-keyout",
            str(key),
            "-out",
            str(crt),
            "-days",
            "825",
            "-subj",
            "/CN=AFW Lab CA/O=AI-Adaptive-Firewall lab",
            "-addext",
            "basicConstraints=critical,CA:TRUE,pathlen:0",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
        )
        key.chmod(0o600)
    return crt


# Extra names clients use: the protected service for WAF01; for CTRL01, the
# operator's SSH tunnel (`-L 18080:10.77.50.10:8080` -> https://localhost:18080/).
EXTRA_DNS = {"WAF01": ["rental.lab.afw"], "CTRL01": ["localhost"]}


def _sans(name: str, ips: list[str]) -> list[str]:
    dns = [f"{name.lower()}.lab.afw", *EXTRA_DNS.get(name, [])]
    return [f"IP:{ip}" for ip in ips] + [f"DNS:{n}" for n in dns]


def _cert_sans(crt: Path) -> set[str]:
    out = subprocess.run(  # noqa: S603
        [OPENSSL, "x509", "-in", str(crt), "-noout", "-ext", "subjectAltName"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    body = out.split("\n", 1)[1] if "\n" in out else ""
    return {s.strip().replace("IP Address:", "IP:") for s in body.split(",") if s.strip()}


def ensure_leaf(
    name: str, ips: list[str], d: Path = PKI_DIR, *, client: bool = False
) -> tuple[Path, Path]:
    """Return (cert, key) for ``name`` with the given IP SANs; created once, and
    re-issued (new key) only if an existing certificate lacks a required SAN.

    ``client=True`` issues a TLS *client* certificate (extendedKeyUsage
    clientAuth), used by sensors to authenticate to the telemetry receiver.
    """
    ensure_ca(d)
    key, crt, csr = d / f"{name}.key", d / f"{name}.pem", d / f"{name}.csr"
    want = _sans(name, ips)
    if not crt.exists() or not set(want) <= _cert_sans(crt):
        san = ",".join(want)
        _run(
            "req",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-nodes",
            "-keyout",
            str(key),
            "-out",
            str(csr),
            "-subj",
            f"/CN={name.lower()}.lab.afw",
        )
        ext = d / f"{name}.ext"
        ext.write_text(
            f"subjectAltName={san}\nextendedKeyUsage={'clientAuth' if client else 'serverAuth'}\n"
            "keyUsage=critical,digitalSignature\nbasicConstraints=CA:FALSE\n"
        )
        _run(
            "x509",
            "-req",
            "-in",
            str(csr),
            "-CA",
            str(d / "lab-ca.pem"),
            "-CAkey",
            str(d / "lab-ca.key"),
            "-CAcreateserial",
            "-out",
            str(crt),
            "-days",
            "397",
            "-extfile",
            str(ext),
        )
        key.chmod(0o600)
        csr.unlink()
        ext.unlink()
    return crt, key
