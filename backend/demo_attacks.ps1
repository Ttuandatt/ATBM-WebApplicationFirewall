# demo_attacks.ps1
# Run a series of simulated attack requests against the demo WAF (127.0.0.1:5000),
# then fetch recent logs from admin API (127.0.0.1:5002/api/logs).
# Usage: Open PowerShell, cd to folder containing this script, then:
#   ./demo_attacks.ps1

# Helper: send GET/POST and return structured result (status & body)
function Send-Request {
    param(
        [string]$Method = "GET",
        [string]$Url,
        [string]$Body = $null,
        [hashtable]$Headers = $null,
        [string]$ContentType = "text/plain"
    )

    try {
        if ($Method -eq "GET") {
            $resp = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 10 -Headers $Headers
            return @{ ok = $true; status = $resp.StatusCode; content = $resp.Content }
        } else {
            $resp = Invoke-WebRequest -Uri $Url -Method $Method -Body $Body -ContentType $ContentType -UseBasicParsing -TimeoutSec 10 -Headers $Headers
            return @{ ok = $true; status = $resp.StatusCode; content = $resp.Content }
        }
    } catch {
        # Try to extract status code & body from exception Response (for non-2xx)
        $err = $_
        $r = $err.Exception.Response
        if ($r -ne $null) {
            try {
                $sc = $r.StatusCode.value__
            } catch {
                $sc = "ERR"
            }
            try {
                $sr = New-Object System.IO.StreamReader($r.GetResponseStream())
                $body = $sr.ReadToEnd()
                $sr.Close()
            } catch {
                $body = $err.Exception.Message
            }
            return @{ ok = $false; status = $sc; content = $body }
        } else {
            return @{ ok = $false; status = "NO_RESPONSE"; content = $err.Exception.Message }
        }
    }
}

# Endpoints
$WAF_BASE = "http://127.0.0.1:5000"
$ADMIN_LOGS = "http://127.0.0.1:5002/api/logs"

# Tests array
$tests = @(
    @{
        name = "CRLF / Header injection (CRLF + Set-Cookie)";
        method = "GET";
        url = "$WAF_BASE/search?q=%0d%0aSet-Cookie:evil=1";
        body = $null;
        contentType = "text/plain";
        note = "Simulates response-splitting/header injection."
    },
    @{
        name = "XPath / LDAP hint (filter=(//* )[1])";
        method = "GET";
        url = "$WAF_BASE/search?q=filter=(//* )[1]";
        body = $null;
        contentType = "text/plain";
        note = "Simulates XPath expression in input."
    },
    @{
        name = "Suspicious long token (90 chars)";
        method = "POST";
        url = "$WAF_BASE/redeem";
        body = ("A" * 90);
        contentType = "text/plain";
        note = "Long alnum token detection."
    },
    @{
        name = "SQL comment / obfuscation (/*...*/)";
        method = "GET";
        url = "$WAF_BASE/search?q=1/*comment*/";
        body = $null;
        contentType = "text/plain";
        note = "SQL comment obfuscation pattern."
    },
    @{
        name = "UNION SELECT (SQLi example)";
        method = "GET";
        url = "$WAF_BASE/search?q=UNION+SELECT+password+FROM+users";
        body = $null;
        contentType = "text/plain";
        note = "UNION-based SQLi payload."
    },
    @{
        name = "Suspicious file extension (.php)";
        method = "GET";
        url = "$WAF_BASE/download?file=shell.php";
        body = $null;
        contentType = "text/plain";
        note = "Access/upload of .php file."
    },
    @{
        name = "Command injection pattern (; whoami)";
        method = "POST";
        url = "$WAF_BASE/comment";
        body = "; whoami";
        contentType = "text/plain";
        note = "Semicolon + command pattern."
    },
    @{
        name = "XSS with <script> tag (POST body)";
        method = "POST";
        url = "$WAF_BASE/comment";
        body = "<script>alert('xss-demo')</script>";
        contentType = "text/plain";
        note = "Classic script tag XSS."
    }
)

Write-Host "=== RuleForge demo: running $(($tests).Count) tests against $WAF_BASE ===`n"

# Run each test
$i = 1
foreach ($t in $tests) {
    Write-Host "[$i/$(($tests).Count)] Test: $($t.name)" -ForegroundColor Cyan
    Write-Host "    Note: $($t.note)"
    Write-Host "    URL: $($t.url)"
    if ($t.method -eq "POST") { Write-Host "    Body: $($t.body.Substring(0,[Math]::Min($t.body.Length,120)))" }

    $res = Send-Request -Method $t.method -Url $t.url -Body $t.body -ContentType $t.contentType
    if ($res.ok) {
        Write-Host "    => Status: $($res.status) (allowed or 2xx) " -ForegroundColor Green
    } else {
        Write-Host "    => Status: $($res.status) (blocked or error) " -ForegroundColor Yellow
    }
    # Print first 300 chars of response content for quick debugging
    $c = $res.content
    if ($null -ne $c) {
        $short = if ($c.Length -gt 300) { $c.Substring(0,300) + "..." } else { $c }
        Write-Host "    Response snippet: $short"
    }
    Write-Host ""
    Start-Sleep -Seconds 1
    $i++
}

# Pause briefly to let WAF write logs
Start-Sleep -Seconds 1

# Fetch logs from admin API
Write-Host "`n=== Fetching admin logs from $ADMIN_LOGS ===" -ForegroundColor Magenta
try {
    $apiResp = Invoke-RestMethod -Uri $ADMIN_LOGS -Method Get -TimeoutSec 10
    if ($apiResp -and $apiResp.logs) {
        $lines = $apiResp.logs
        $count = $lines.Count
        Write-Host "Total log lines returned: $count"
        $take = 20
        $startIndex = if ($count -gt $take) { $count - $take } else { 0 }
        Write-Host "Showing last $take log lines (or fewer):" -ForegroundColor Green
        for ($j = $startIndex; $j -lt $count; $j++) {
            Write-Host $lines[$j]
        }
    } else {
        Write-Host "No logs field in admin response. Raw response:"
        Write-Output $apiResp
    }
} catch {
    Write-Host "Failed to fetch admin logs: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n=== Demo finished ==="
