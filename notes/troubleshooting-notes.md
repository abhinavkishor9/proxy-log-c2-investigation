# troubleshooting-notes.md

# Troubleshooting Notes

## 1. Incorrect HTTP Listener Prefix

### Problem

The listener was initially configured with an incomplete prefix:

```text
http://127.0.0
```

The intended endpoint was:

```text
http://127.0.0.1:8080/
```

### Correct Configuration

```powershell
$Listener = [System.Net.HttpListener]::new()
$Listener.Prefixes.Add("http://127.0.0.1:8080/")
$Listener.Start()
```

### Lesson

Always verify the exact listener address and port before generating traffic.

---

## 2. Incorrect HTTP Request URL

### Problem

The initial request format contained an invalid URL similar to:

```text
http://127.0.0checkin
```

The intended request was:

```text
http://127.0.0.1:8080/checkin
```

### Correct Command

```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:8080/checkin" -UseBasicParsing
```

### Lesson

A malformed URL can prevent the intended HTTP transaction from reaching the listener and can create misleading downstream telemetry results.

---

## 3. Listener Loop Blocks the Current PowerShell Session

### Problem

The HTTP listener uses:

```powershell
while ($Listener.IsListening) {
    $Context = $Listener.GetContext()
    ...
}
```

`GetContext()` waits for an incoming request.

Therefore, the same PowerShell session cannot continue to the traffic-generation commands while the listener loop is actively waiting.

### Correct Approach

Run the listener in one PowerShell window and generate requests from another PowerShell window.

```text
PowerShell Window 1
    ↓
HTTP Listener

PowerShell Window 2
    ↓
Invoke-WebRequest
```

### Lesson

A blocking listener and a traffic generator need separate execution contexts unless the listener is explicitly implemented asynchronously.

---

## 4. Sysmon Event ID 3 Did Not Produce the Expected 8080 Event

### Problem

The investigation attempted to locate a network event containing:

```text
127.0.0.1
```

and:

```text
8080
```

The query did not produce a matching event.

As a result:

```powershell
$NetworkEvent
```

was null.

### Error

```text
You cannot call a method on a null-valued expression.
```

This occurred when:

```powershell
$NetworkEvent.TimeCreated.AddMinutes(-2)
```

was executed.

### Correct Approach

Validate the event first:

```powershell
$NetworkEvent = Get-WinEvent -FilterHashtable @{
    LogName = "Microsoft-Windows-Sysmon/Operational"
    Id = 3
} -MaxEvents 500 |
Where-Object {
    $_.Message -match "8080"
} |
Select-Object -First 1

$NetworkEvent
```

Only calculate the time window if an event was actually returned.

### Lesson

Never perform timestamp calculations on an event object before verifying that the event exists.

---

## 5. Do Not Assume Localhost Traffic Will Produce the Expected Sysmon Event

The controlled HTTP requests were generated against:

```text
127.0.0.1:8080
```

However, the expected Sysmon Event ID 3 record containing the port was not established through the investigation query.

This does not prove that the HTTP requests failed.

It means only that the expected Sysmon network telemetry was not identified.

### Correct Interpretation

```text
HTTP request:
Confirmed through controlled application activity.

Sysmon EID 3 for 127.0.0.1:8080:
Not established.

Process-to-network attribution:
Inconclusive.
```

---

## 6. Do Not Treat Temporal Proximity as Attribution

A Process Create event occurring near a network event does not automatically prove that the process generated the connection.

Strong attribution should ideally include:

- Process ID
- Image
- Command line
- Timestamp
- Destination
- Network event
- Parent process
- User

Without sufficient fields, the correct classification is:

```text
Potential correlation
```

rather than:

```text
Confirmed attribution
```

---

## 7. Do Not Treat Beaconing as Proof of C2

The lab intentionally generated requests at regular intervals.

For example:

```text
Request
↓
5 seconds
↓
Request
↓
5 seconds
↓
Request
```

This resembles beaconing behavior.

However, legitimate applications can also communicate periodically.

Therefore:

```text
Periodic traffic ≠ automatic C2
```

Additional evidence would be required in a real investigation.

---

## 8. Proxy-Style Logs Are Not the Same as Enterprise Proxy Logs

The lab generated:

```text
Proxy-Requests.csv
```

using the controlled PowerShell HTTP listener.

This is useful for learning proxy-log investigation techniques, but it is not equivalent to telemetry from products such as an enterprise secure web gateway or forward proxy.

The evidence should therefore be described as:

```text
Proxy-style HTTP request telemetry
```

rather than a production proxy log.

---

## 9. Wazuh Correlation Must Remain Endpoint-Specific

For endpoint investigation, use:

```text
agent.id:"001" AND agent.name:"DESKTOP-9MMM37V"
```

Do not treat manager-side Wazuh events from:

```text
agent.id:"000"
```

as endpoint evidence.

If Wazuh does not contain a matching network or process event, document the telemetry limitation instead of creating an assumed correlation.

---

## 10. Validate the Controlled Destination Before Testing

Before generating requests:

```powershell
Get-NetTCPConnection -LocalPort 8080 -ErrorAction SilentlyContinue
```

After starting the listener, verify that port `8080` is listening.

After stopping the listener, repeat the command to confirm that the listener has stopped.

This helps distinguish an application/listener problem from an endpoint telemetry problem.

---

## 11. Evidence Collection Should Follow the Activity

The preferred sequence is:

```text
Baseline
    ↓
Start Listener
    ↓
Verify Listener
    ↓
Generate Request
    ↓
Verify Proxy Log
    ↓
Generate Repeated Traffic
    ↓
Review Proxy Log
    ↓
Review Sysmon
    ↓
Review Wazuh
    ↓
Correlate
    ↓
Assess
```

This prevents the investigation from relying on assumptions about events that were never confirmed.

---

## 12. Final Troubleshooting Principle

When expected telemetry is missing:

> **Document the visibility limitation instead of filling the gap with assumptions.**

For this investigation, the most important example was the missing confirmed Sysmon `127.0.0.1:8080` event. The correct result was not to invent process attribution, but to classify the correlation as inconclusive.
