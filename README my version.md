# proxy-log-c2-investigation

## Overview
A proxy log C2 investigation examines outbound web traffic to identify patterns that could indicate command-and-control communication.

Malware often communicates with its C2 infrastructure over HTTP or HTTPS because web traffic is common in enterprise environments. Instead of using obviously malicious protocols, an implant may periodically contact a remote server, request instructions, send system information, or receive commands.

Proxy logs can provide valuable evidence such as:

Source host or IP
Destination domain or IP
Request URI
HTTP method
HTTP status code
User-Agent
Request timestamp
Response size
Repeated request intervals
Frequency of communication

A common C2 characteristic is beaconing: the endpoint contacts the same destination at relatively regular intervals.

However, regular HTTP traffic does not automatically mean C2. Browsers, Windows services, cloud applications, software updates, security agents, and telemetry services can all generate periodic traffic.

This lab investigates simulated HTTP command-and-control (C2) communication using a controlled local HTTP listener, proxy-style request logging, repeated beacon-like traffic, and Windows endpoint telemetry.

The investigation was performed on a Windows endpoint using PowerShell. A local HTTP listener was used to generate controlled web traffic without communicating with real malicious infrastructure. The resulting requests were recorded in a structured CSV file and analyzed for URI frequency, User-Agent patterns, timing, and network activity.

The investigation also examined Sysmon Event ID 3 network telemetry to determine whether the controlled HTTP activity could be independently observed at the endpoint level.

The central principle of this investigation is that **periodic or repetitive HTTP traffic is an indicator for investigation, not proof of C2**.

## Environment

| Component | Value |
|---|---|
| Host | `DESKTOP-9MMM37V` |
| Operating System | Windows 11 Pro |
| Shell | PowerShell 7.6.6 |
| Sysmon | 4.91 |
| Wazuh Agent | `001` |
| Lab Path | `C:\ProxyLogC2Lab` |
| Evidence Path | `C:\ProxyLogC2Lab\Evidence` |
| Controlled Destination | `127.0.0.1:8080` |
| Protocol | HTTP |

## Lab Scenario

A Windows endpoint is being investigated for potentially suspicious HTTP communication that may resemble command-and-control (C2) beaconing. The investigation focuses on how repeated web requests can be identified, documented, and correlated with endpoint telemetry without immediately assuming that the activity is malicious.

A controlled local HTTP service will be used to generate the activity safely. The simulated destination is `127.0.0.1:8080`, allowing the investigation to reproduce HTTP communication without connecting to real C2 infrastructure. Requests will include repeated and varied URI paths so that timing, frequency, and request patterns can be examined.

The investigation will capture the generated HTTP activity as proxy-style evidence. The collected information will include request timestamps, HTTP methods, requested URIs, User-Agent values, and remote endpoints. Repeated requests will then be analyzed to determine whether they demonstrate characteristics commonly associated with beaconing, such as regular intervals or repeated communication with the same destination.

The investigation will also examine Windows endpoint telemetry, particularly Sysmon Event ID 3 network connection events and Event ID 1 process creation events. The analyst will attempt to determine whether the controlled network activity can be associated with a specific process, while avoiding attribution based only on events occurring at approximately the same time.

The investigation should also account for telemetry limitations. If a matching `127.0.0.1:8080` network event or sufficient process information is not available, the absence should be documented as a visibility limitation rather than interpreted as proof that the communication did not occur.

The final assessment should distinguish between confirmed controlled activity, suspicious behavioral indicators, and evidence that would be required to establish genuine C2 communication.

The core investigation principle is:

> **Beacon-like HTTP behavior is an indicator for investigation, not proof of malicious C2.**

## Lab Scenario

A Windows endpoint is being investigated for potentially suspicious HTTP communication that may resemble command-and-control (C2) beaconing. The purpose of the investigation is to understand how repeated web requests can be identified and correlated with endpoint telemetry without automatically treating periodic communication as malicious.

The investigation uses a controlled local HTTP service so that the activity can be generated safely without contacting real external infrastructure. The simulated destination is `127.0.0.1:8080`, where HTTP requests will be generated at controlled intervals and recorded as proxy-style request data.

The investigation will focus on the following evidence:

- Request timestamps and communication intervals.
- HTTP methods and requested URI paths.
- User-Agent values and remote endpoint information.
- Frequency of repeated requests and URI patterns.
- Sysmon Event ID 3 network connection telemetry.
- Sysmon Event ID 1 process creation telemetry.
- Available Wazuh endpoint telemetry during the investigation window.
- Correlation between network activity and process execution.

Repeated `/checkin` requests will be generated to simulate beacon-like behavior, followed by additional URI paths such as `/status`, `/config`, and `/update`. The resulting request data will be reviewed to determine whether the communication shows regular timing, repeated destinations, or other characteristics that may warrant further investigation.

The analyst will then compare the proxy-style evidence with Windows telemetry. Process-to-network attribution will only be made when the available evidence supports the relationship. Events that occur close together in time will not automatically be considered part of the same activity.

Telemetry limitations will also form part of the investigation. If Sysmon does not provide a matching network event for port `8080`, or if process details are incomplete, the limitation will be documented rather than replaced with an assumption.

The final assessment should determine whether the observed behavior represents:

- Expected controlled activity.
- Suspicious beacon-like behavior requiring further investigation.
- Evidence consistent with C2 communication.
- Insufficient telemetry to make a stronger determination.

The investigation follows the principle that **beacon-like traffic is a behavioral indicator, not proof of malicious C2 or compromise**.

## Lab Architecture

```text
PowerShell Client
       |
       | HTTP
       v
127.0.0.1:8080
       |
       v
PowerShell HttpListener
       |
       v
Proxy-Requests.csv
       |
       +--------------------+
       |                    |
       v                    v
URI/User-Agent         Timestamp Analysis
       |
       v
Sysmon Event ID 3
       |
       v
Endpoint Correlation
```

## Controlled HTTP Listener

The investigation used PowerShell's `System.Net.HttpListener` to create a local HTTP service.

The intended listener endpoint was:

```text
http://127.0.0.1:8080/
```

The server returned a simple `200 OK` response with the body:

```text
OK
```

The listener recorded:

- Timestamp
- HTTP method
- Requested URI
- User-Agent
- Remote endpoint

These fields were written to:

```text
C:\ProxyLogC2Lab\Evidence\Proxy-Requests.csv
```

## Simulated Beacon Activity

The lab generated repeated HTTP requests using PowerShell.

The primary simulated beacon pattern used ten requests with a five-second interval:

```powershell
1..10 | ForEach-Object {
    Invoke-WebRequest -Uri "http://127.0.0.1:8080/checkin" -UseBasicParsing | Out-Null
    Start-Sleep -Seconds 5
}
```

Additional URI patterns were generated using:

```text
/checkin
/status
/config
/update
/checkin
```

with short delays between requests.

This was intentionally controlled traffic and should not be interpreted as real C2 activity.

## Proxy-Style Evidence

The generated request log was analyzed using PowerShell.

URI frequency:

```powershell
$Requests |
    Group-Object URI |
    Select-Object Name, Count
```

User-Agent frequency:

```powershell
$Requests |
    Group-Object UserAgent |
    Select-Object Name, Count
```

The resulting evidence files included:

```text
Proxy-Requests.csv
Proxy-Requests-Review.txt
URI-Frequency.txt
UserAgent-Frequency.txt
```

## Sysmon Investigation

Sysmon Event ID 3 was reviewed for network connection activity.

The initial investigation searched for localhost-related traffic:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = "Microsoft-Windows-Sysmon/Operational"
    Id = 3
} -MaxEvents 500 |
Where-Object {
    $_.Message -match "127.0.0.1"
} |
Select-Object TimeCreated, Id, Message
```

The investigation then attempted to determine whether a specific `127.0.0.1:8080` network event could be identified and correlated with a Process Create event.

## Process Attribution

Process attribution was treated cautiously.

The presence of PowerShell during the lab does not by itself prove that every network event observed near the investigation time was generated by the same process.

The intended correlation chain was:

```text
HTTP Request
    ↓
127.0.0.1:8080
    ↓
Sysmon Event ID 3
    ↓
Timestamp
    ↓
Sysmon Event ID 1
    ↓
PowerShell Process
    ↓
Command Line / Process ID
```

During the investigation, the specific `8080` network event required for this correlation was not successfully established through the Sysmon query. As a result, process-to-network attribution was not treated as confirmed.

## Evidence Assessment

| Finding | Assessment |
|---|---|
| Local HTTP listener | Confirmed |
| Controlled HTTP requests | Confirmed |
| Repeated request pattern | Confirmed by generated traffic |
| URI variation | Confirmed |
| Proxy-style logging | Confirmed |
| Localhost destination | Confirmed |
| Real external C2 | Not established |
| Malicious infrastructure | Not established |
| Sysmon process-to-8080 attribution | Not established |
| Actual compromise | Not established |

## Important Troubleshooting Finding

The investigation initially used malformed localhost URLs such as:

```text
http://127.0.0checkin
```

and the listener prefix was also entered incorrectly in the combined session.

The correct listener prefix is:

```text
http://127.0.0.1:8080/
```

and the correct request format is:

```text
http://127.0.0.1:8080/checkin
```

These corrections are important because malformed URLs can invalidate the controlled traffic-generation stage and make later telemetry correlation misleading.

## Limitations

The lab demonstrates proxy-style investigation methodology rather than a real enterprise proxy deployment.

Important limitations include:

- The traffic was generated locally.
- No real malicious C2 infrastructure was contacted.
- The proxy log was created by the controlled PowerShell listener rather than an enterprise proxy appliance.
- Sysmon did not provide a confirmed `127.0.0.1:8080` network event for process attribution during the investigation.
- A missing Sysmon event cannot be interpreted as proof that the HTTP request did not occur.
- Temporal proximity alone is insufficient to establish process attribution.
- The simulated traffic intentionally resembles beaconing and therefore must not be classified as malicious solely because of its periodicity.

