import json
import subprocess


POWERSHELL_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$utf8 = New-Object System.Text.UTF8Encoding($false)
[Console]::OutputEncoding = $utf8
$OutputEncoding = $utf8
$paths = [Console]::In.ReadToEnd() | ConvertFrom-Json
$results = foreach ($path in $paths) {
    try {
        $signature = Get-AuthenticodeSignature -LiteralPath $path -ErrorAction Stop
        $certificate = $signature.SignerCertificate
        [PSCustomObject]@{
            path = $path
            collection_status = 'collected'
            error = $null
            status = [string]$signature.Status
            status_message = $signature.StatusMessage
            signature_type = [string]$signature.SignatureType
            subject = if ($certificate) { $certificate.Subject } else { $null }
            issuer = if ($certificate) { $certificate.Issuer } else { $null }
            thumbprint = if ($certificate) { $certificate.Thumbprint } else { $null }
            valid_from = if ($certificate) { $certificate.NotBefore.ToString('o') } else { $null }
            valid_until = if ($certificate) { $certificate.NotAfter.ToString('o') } else { $null }
        }
    } catch {
        [PSCustomObject]@{
            path = $path
            collection_status = 'error'
            error = $_.Exception.Message
            status = $null
            status_message = $null
            signature_type = $null
            subject = $null
            issuer = $null
            thumbprint = $null
            valid_from = $null
            valid_until = $null
        }
    }
}
[Console]::Out.Write((ConvertTo-Json -InputObject @($results) -Depth 4 -Compress))
"""


def _failure(paths, status, message):
    return {path.lower(): {
        "path": path, "collection_status": status, "error": message,
        "status": None, "status_message": None, "signature_type": None,
        "subject": None, "issuer": None, "thumbprint": None,
        "valid_from": None, "valid_until": None,
    } for path in paths}


def collect_signatures(executables):
    paths = [item["path"] for item in executables if item.get("path")]
    if not paths:
        return {}
    try:
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
             POWERSHELL_SCRIPT],
            # JSON escapes keep stdin ASCII even for non-ASCII Windows paths.
            input=json.dumps(paths, ensure_ascii=True),
            capture_output=True, text=True, encoding="utf-8", timeout=120,
        )
        if result.returncode != 0:
            return _failure(paths, "error", result.stderr.strip() or "PowerShell failed.")
        data = json.loads(result.stdout.lstrip("\ufeff"))
        if isinstance(data, dict):
            data = [data]
        if not isinstance(data, list):
            raise ValueError("Expected an array of signature records.")
        records = {}
        for item in data:
            if not isinstance(item, dict) or not isinstance(item.get("path"), str):
                raise ValueError("Invalid signature record.")
            if item.get("collection_status") not in {"collected", "error"}:
                raise ValueError("Missing signature collection status.")
            records[item["path"].lower()] = item
        missing = _failure(paths, "error", "No signature result was returned for this path.")
        return {path.lower(): records.get(path.lower(), missing[path.lower()]) for path in paths}
    except subprocess.TimeoutExpired:
        return _failure(paths, "timeout", "Signature collection exceeded 120 seconds.")
    except FileNotFoundError:
        return _failure(paths, "unavailable", "Windows PowerShell (powershell.exe) was not found.")
    except (subprocess.SubprocessError, OSError, ValueError, UnicodeError) as error:
        return _failure(paths, "error", str(error))
