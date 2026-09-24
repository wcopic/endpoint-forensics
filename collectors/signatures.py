import json
import subprocess


def collect_signatures(executables):

    paths = [
        executable["path"]
        for executable in executables
        if executable.get("path")
    ]

    if not paths:
        return {}


    powershell_script = r"""
$paths = [Console]::In.ReadToEnd() | ConvertFrom-Json

$results = foreach ($path in $paths) {

    try {

        $signature = Get-AuthenticodeSignature `
            -LiteralPath $path

        $certificate = $signature.SignerCertificate


        [PSCustomObject]@{
            path = $path

            status = [string]$signature.Status

            status_message =
                $signature.StatusMessage

            signature_type =
                [string]$signature.SignatureType

            subject =
                if ($certificate) {
                    $certificate.Subject
                } else {
                    $null
                }

            issuer =
                if ($certificate) {
                    $certificate.Issuer
                } else {
                    $null
                }

            thumbprint =
                if ($certificate) {
                    $certificate.Thumbprint
                } else {
                    $null
                }

            valid_from =
                if ($certificate) {
                    $certificate.NotBefore.ToString("o")
                } else {
                    $null
                }

            valid_until =
                if ($certificate) {
                    $certificate.NotAfter.ToString("o")
                } else {
                    $null
                }
        }

    } catch {

        [PSCustomObject]@{
            path = $path
            status = "Error"
            status_message = $_.Exception.Message
            signature_type = $null
            subject = $null
            issuer = $null
            thumbprint = $null
            valid_from = $null
            valid_until = $null
        }
    }
}

ConvertTo-Json `
    -InputObject @($results) `
    -Depth 4 `
    -Compress
"""


    try:

        result = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                powershell_script
            ],
            input=json.dumps(paths),
            capture_output=True,
            text=True,
            timeout=120
        )


        if result.returncode != 0:
            return {}


        data = json.loads(
            result.stdout
        )


        if isinstance(data, dict):
            data = [data]


        return {
            item["path"].lower(): item
            for item in data
            if item.get("path")
        }


    except (
        subprocess.SubprocessError,
        json.JSONDecodeError,
        OSError
    ):
        return {}