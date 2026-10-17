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


EXTRA_DNS = {"WAF01": ["rental.lab.afw"]}  # names clients use for the protected service


def ensure_leaf(name: str, ips: list[str], d: Path = PKI_DIR) -> tuple[Path, Path]:
    """Return (cert, key) for ``name`` with the given IP SANs; created once."""
    ensure_ca(d)
    key, crt, csr = d / f"{name}.key", d / f"{name}.pem", d / f"{name}.csr"
    if not crt.exists():
        dns = [f"{name.lower()}.lab.afw", *EXTRA_DNS.get(name, [])]
        san = ",".join([f"IP:{ip}" for ip in ips] + [f"DNS:{n}" for n in dns])
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
            f"subjectAltName={san}\nextendedKeyUsage=serverAuth\n"
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
