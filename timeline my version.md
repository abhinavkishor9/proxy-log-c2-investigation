# Investigation Timeline

| Sequence | Activity | Evidence / Result |
|---:|---|---|
| 1 | Investigation workspace created | `C:\ProxyLogC2Lab\Evidence` |
| 2 | Investigation time recorded | `Investigation-Time.txt` |
| 3 | Host baseline collected | `Host-Baseline.txt` |
| 4 | User context collected | `User-Context.txt` |
| 5 | Network baseline collected | `Network-Baseline.txt` |
| 6 | Controlled destination documented | `127.0.0.1:8080` |
| 7 | Local HTTP listener configured | PowerShell `HttpListener` |
| 8 | HTTP request logging configured | `Proxy-Requests.csv` |
| 9 | Controlled HTTP request generated | `/checkin` |
| 10 | Repeated HTTP traffic generated | Ten `/checkin` requests with approximately five-second intervals |
| 11 | Additional URI activity generated | `/checkin`, `/status`, `/config`, `/update`, `/checkin` |
| 12 | Proxy-style request log reviewed | Request metadata available for analysis |
| 13 | URI frequency analyzed | `URI-Frequency.txt` |
| 14 | User-Agent frequency analyzed | `UserAgent-Frequency.txt` |
| 15 | Request review export created | `Proxy-Requests-Review.txt` |
| 16 | Sysmon Event ID 3 reviewed | Localhost network telemetry investigated |
| 17 | Port `8080` correlation attempted | No confirmed matching Sysmon network event established |
| 18 | Process attribution attempted | Could not establish definitive Sysmon EID 1 → `8080` relationship |
| 19 | Null-event error encountered | `$NetworkEvent` was null during timestamp calculation |
| 20 | Correlation methodology corrected | Event existence validated before timestamp operations |
| 21 | Telemetry limitation documented | Missing matching Sysmon network event treated as visibility limitation |
| 22 | Final assessment completed | Controlled beacon-like HTTP activity confirmed; malicious C2 not established |

