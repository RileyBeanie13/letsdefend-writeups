# SOC Alert Investigation: Detected Suspicious XLS File

<img width="1065" height="198" alt="image" src="https://github.com/user-attachments/assets/8bef0a8f-6b50-4e18-aab8-6ab14f181704" />

Our investigation starts here with a medium-severity **LetsDefend SOC Alert: SOC138 - Detected Suspicious Xls File**. This is a **Malware** alert, so I'm going to be looking for suspicious files, endpoint activity, and any behavior that may indicate malware execution or compromise.

To begin the investigation, I've created a case for the alert and I'll work through the provided playbook.


## Playbook Step 1: Define Threat Indicator

The first step of the playbook asks me to define the threat indicator related to the alert. Since this is a malware alert, I need to identify what suspicious indicator is associated with the detection before making any decisions.

For this step, I’m going to review the alert details and determine which indicator is most relevant to the investigation, such as a suspicious file, file hash, process, or other malware-related artifact.

<img width="798" height="364" alt="image" src="https://github.com/user-attachments/assets/2a6e2953-d292-4919-a5b8-529ffeb162e4" />

After expanding the original alert, I’ve been able to review the available details and identify the indicator that triggered the malware detection. 

<img width="1065" height="628" alt="image" src="https://github.com/user-attachments/assets/c68dd650-faa2-46c3-a6b6-71e979b39134" />

After expanding the alert, I identified the main details tied to the malware detection. The alert involved the host `Sofia` with the source address `172.16.17.56`. The file involved was named `ORDER SHEET & SPEC.xlsm`, and the file hash was:

`7ccf88c0bbe3b29bf19d877c4596a8d4`

The file size was listed as `2.66 MB`, and the device action was `Allowed`, meaning the file was not blocked by the security control.

I first searched the file hash in Threat Intelligence, but I did not find any results. I also searched the mailbox for references to `ORDER SHEET & SPEC.xlsm` to check whether the file may have been delivered through an email attachment, but I did not find any related emails or attachments that pertained to `Sofia`.

Next, I checked Endpoint Security for activity on `Sofia`. The endpoint returned a `POwersheLL.exe` process entry and a terminal history containing `cd`, `dir`, and an encoded PowerShell command using randomized casing and a base64 payload. However, all of these artifacts are dated October 2020, roughly five months before the alert fired on March 13, 2021, and no activity was logged within the alert timeframe. Because of this, I could not confirm execution or endpoint behavior from EDR evidence.

<img width="1170" height="752" alt="image" src="https://github.com/user-attachments/assets/ff8e9c82-37b2-4649-bf14-57a9dd8e713d" />

<img width="1171" height="749" alt="image" src="https://github.com/user-attachments/assets/32c887c7-e8cc-4a95-a15f-6632e164e18f" />


I then searched Log Management for activity from the source address `172.16.17.56` and found two related `Firewall` logs. 

Both of these logs showed traffic from `172.16.17.56` to the destination address `177.53.143.89` over port `443` on `Mar. 13, 2021, 08:20 PM` which was the same time the alert fired. Not to mention, there's this data I found in the raw logs:

`....}...y..K|Í|.....y.<§¢jJê#.....mrZ¡.Ã..../.5....À.À.À.À..2.8.......8ÿ.............................`

`
....5...1..K|ÍtV.kE...Ù.c..b§.7rÊb.?&........ÿ..`

The raw logs also contain non-printable binary data rendered as escaped characters rather than readable text. Given the traffic is over port `443`, this could be raw packet data from the TLS session.


<img width="1316" height="911" alt="image" src="https://github.com/user-attachments/assets/844699b8-5cbd-442c-ad4e-a49d965bdb26" />

Before analyzing the file itself, I checked the destination address `177.53.143.89` on VirusTotal. The IP returned `0/91` vendor detections and appeared clean at first glance, though it carried a community score of `-4`. However, the Relations tab showed 10+ detected files communicating with this address, including `ORDER SHEET & SPEC.xlsm`, which is the same file referenced in the original alert. The address is registered to AS 53243 (Brasil Site Informatica LTDA) in Brazil.

<img width="1316" height="914" alt="image" src="https://github.com/user-attachments/assets/b8f8f994-2a8f-4bf4-993d-aede83b74855" />

I then analyzed the file hash from the original alert. VirusTotal flagged it `44/63` malicious with a community score of `-10`, with a popular threat label of `trojan.acao/docdl` and threat categories of trojan, dropper, and downloader.

<img width="1316" height="914" alt="image" src="https://github.com/user-attachments/assets/67897115-5bb4-4d58-a4b9-4260abf06440" />

The Code Insights section identified the following macro behaviors:
- **Obfuscation** — heavily obfuscated variable and function names, strings constructed piece by piece, and decoy comments intended to mislead analysis
- **Base64 decoding** — a variable assigned an encoded string that is later decoded and used alongside file system operations
- **Suspicious function calls** — use of `ShellExecute` and `CreateObject` to launch external programs
- **Download and execute** — a subroutine that retrieves a file from a remote URL, writes it to disk, and executes it via `ShellExecute`, with both the URL and filename obfuscated
- **Self-replication** — an `Auto_Open` subroutine that writes the macro code to a file, allowing it to spread to other documents

The file also carried tags including `macros`, `auto-open`, `exploit`, `cve-2017-11882`, `executes-dropped-file`, and `run-dll`.

For the threat indicator, I selected `Other` because the file's behavior spans multiple categories rather than fitting a single one. The MITRE ATT&CK mapping on VirusTotal supports this:

- **`T1518` — Software Discovery**: the sample contains strings referencing AV process names, indicating it enumerates and attempts to terminate security products
- **`T1497` — Virtualization/Sandbox Evasion**: evasion loops and anti-VM checks designed to hinder analysis
- **`T1542.003` — Pre-OS Boot: Bootkit**: persistence achieved by modifying components loaded before the operating system
- **Command and Control**: multiple additional techniques listed, consistent with the outbound TLS session to `177.53.143.89` observed in the firewall logs

Combined with the download-and-execute and self-replication behavior in the macro, the sample functions as a dropper, downloader, and trojan simultaneously, which is why no single threat indicator category was sufficient.


## Playbook Step 2: Check Whether the Malware Was Quarantined or Cleaned

The next step of the playbook asks me to determine whether the detected malware was quarantined or removed from the affected endpoint. To verify this, I need to review Log Management and Endpoint Security for evidence that the file was blocked, quarantined, deleted, or otherwise cleaned by a security control.

<img width="800" height="417" alt="image" src="https://github.com/user-attachments/assets/7d0d0e77-4704-4615-ac8b-dc2b6565489d" />

I checked `Sofia` in Endpoint Security and saw that the device was not contained. The original alert also showed a device action of `Allowed`, meaning `ORDER SHEET & SPEC.xlsm` was not blocked on delivery, and Log Management showed successful outbound traffic from `172.16.17.56` to `177.53.143.89` at the time the alert fired. Since the file was permitted and the resulting connection completed, I found no evidence that it had been quarantined or cleaned, so I selected **Not Quarantined** in the playbook.


## Playbook Step 3: Analyze Malware

The next step of the playbook asks me to analyze the file using third-party malware analysis tools and determine whether it is malicious. It also asks me to review the results for any command-and-control addresses or other suspicious network indicators.

<img width="796" height="482" alt="image" src="https://github.com/user-attachments/assets/bb9ea680-3711-40bb-813c-32839880390b" />

Based on the VirusTotal results reviewed earlier, a 44/63 detection rate, a `trojan.acao/docdl` threat label, macro Code Insights showing obfuscation, download-and-execute behavior, and self-replication via `Auto_Open`, along with MITRE ATT&CK techniques covering AV discovery (`T1518`), sandbox evasion (`T1497`), and bootkit persistence (`T1542.003`), the file showed strong evidence of malicious behavior.

Because of this, I selected **Malicious** in the playbook.


## Playbook Step 4: Check Whether the C2 Address Was Accessed

The next step of the playbook asks me to determine whether the affected device accessed a command-and-control address associated with the malicious file.

<img width="797" height="483" alt="image" src="https://github.com/user-attachments/assets/b9aeed7f-eb0f-4d57-ba1d-5a264fef23cf" />

While reviewing the behavior of the original file hash in VirusTotal, I looked for network activity that could identify a possible C2 address. Although VirusTotal listed multiple related network indicators, I could only clearly connect one address to the activity observed in Log Management:

`177.53.143.89`

<img width="1318" height="289" alt="image" src="https://github.com/user-attachments/assets/df461867-eb27-4ed3-a43e-4936758c353c" />

In VirusTotal, I could see that this IP address has the most sandbox reports amongst other IPs that were listed in IP traffic. 

<img width="1317" height="907" alt="image" src="https://github.com/user-attachments/assets/8d75a050-3732-438e-a320-67c5a6f4f4a1" />

The Network Analysis results showed that the malware sample contacted `177.53.143.89` over TCP port `443`. The address was also geolocated to `Brazil`, confirming that it was external to the company network.

This matched the Log Management event showing the affected device at `172.16.17.56` communicating with `177.53.143.89`. 

Based on the malware behavior in Hybrid Analysis, VirusTotal and the matching network log, I determined that the address was accessed and selected **Accessed** in the playbook.


## Playbook Step 5: Containment

The next step of the playbook asks me to contain the affected user machine through Endpoint Security. Since the malware was confirmed as malicious and the affected device accessed an address associated with the malware’s network activity, containment is necessary to restrict further communication and reduce the potential impact.

<img width="798" height="435" alt="image" src="https://github.com/user-attachments/assets/baacd9f2-949b-4823-bc96-cc1935bc2e86" />

I went to Endpoint Security, contained the affected machine, and then proceeded to the next step of the playbook.

<img width="999" height="671" alt="image" src="https://github.com/user-attachments/assets/78bddb40-7791-4048-acdf-a715046ee7f8" />


## Playbook Step 6: Add Artifacts

The next step of the playbook asks me to add the relevant indicators collected during the investigation as artifacts.

<img width="798" height="446" alt="image" src="https://github.com/user-attachments/assets/18ed98a5-b0df-4962-b06e-67b89478c4ec" />

I added the following artifacts:

- **IP Address:** `172.16.17.56`  
  Internal IP address of the affected endpoint `Sofia`, used by the primary user `Sofia2020`.
  
- **IP Address:** `177.53.143.89`  
  External destination address contacted by the affected endpoint over port `443` at the time the alert fired. VirusTotal showed `0/91` detections, but the Relations tab listed 10+ malicious files communicating with this address, including the file from this alert.
  
- **MD5 Hash:** `7ccf88c0bbe3b29bf19d877c4596a8d4`  
  MD5 hash of the malicious file `ORDER SHEET & SPEC.xlsm`. VirusTotal flagged the file `44/63` malicious with a threat label of `trojan.acao/docdl`.


  
## Playbook Step 7: Analyst Notes

The next step of the playbook asks me to add analyst notes for the case. I used this section to summarize the main findings from the investigation, including why the traffic looked malicious and whether there was evidence that the attack succeeded.

<img width="798" height="510" alt="image" src="https://github.com/user-attachments/assets/8efe0cdd-e6bb-45a2-9893-58cec5ea7d53" />

**Analyst Note:** On `Mar. 13, 2021, at 08:20 PM`, the system detected a suspicious XLS file on the internal endpoint `Sofia` at `172.16.17.56`, used by the primary user `Sofia2020`. The file was named `ORDER SHEET & SPEC.xlsm`, with the MD5 hash `7ccf88c0bbe3b29bf19d877c4596a8d4`. The device action was `Allowed`, meaning the file was not blocked when the alert was generated.

Log Management showed two Firewall logs with traffic from `172.16.17.56` to `177.53.143.89` over port `443` on `Mar. 13, 2021, at 08:20 PM`, matching the time the alert fired. The raw logs contained non-printable binary data consistent with an encrypted TLS session, so no payload contents were recoverable.

I checked `177.53.143.89` on VirusTotal. The IP returned `0/91` detections with a community score of `-4`, but the Relations tab showed 10+ detected files communicating with this address, including `ORDER SHEET & SPEC.xlsm`. The address is registered to AS 53243 (Brasil Site Informatica LTDA) in Brazil.

I then analyzed the file hash, which was flagged by `44/63` vendors with a threat label of `trojan.acao/docdl` and categories of trojan, dropper, and downloader. Code Insights identified heavily obfuscated variable and function names, decoy comments meant to mislead analysis, a Base64 string decoded and used alongside file system operations, use of `ShellExecute` and `CreateObject`, a subroutine that downloads a remote file and executes it, and an `Auto_Open` subroutine that writes the macro to a file for self-replication. Tags included `macros`, `auto-open`, `exploit`, `cve-2017-11882`, and `executes-dropped-file`.

The MITRE ATT&CK mappings spanned discovery, evasion, persistence, and command and control, including Software Discovery (`T1518`) with strings referencing AV process names, Virtualization/Sandbox Evasion (`T1497`) using evasion loops and anti-VM checks, and Pre-OS Boot: Bootkit (`T1542.003`). I selected `Other` as the threat indicator, since the sample functions as a dropper, downloader, and trojan simultaneously.

The malware was not quarantined or cleaned. The device action was `Allowed` and Log Management confirmed the outbound connection completed successfully.

Based on the VirusTotal detections, malicious macro behavior, MITRE ATT&CK mappings, and the matching outbound connection to an address associated with the sample, I assessed `ORDER SHEET & SPEC.xlsm` as malicious. Since the file was not quarantined and the endpoint contacted the suspected C2 address, I contained `Sofia` through Endpoint Security to restrict further activity.


## Playbook Step 8: Finish the Playbook!

The final playbook step was to confirm the investigation and close the case. At this point, I had already added the relevant artifacts, summarized my findings into the analyst notes, and completed all the required playbook actions.

<img width="798" height="346" alt="image" src="https://github.com/user-attachments/assets/d7819091-ed53-4609-a61c-512030a78b18" />


## Final Verdict and Closing Case: True Positive

After completing the playbook, I reviewed the evidence collected throughout the investigation to determine whether the alert was a true positive or false positive.

My final verdict is that this alert is a **True Positive**. The file `ORDER SHEET & SPEC.xlsm`, with the MD5 hash `7ccf88c0bbe3b29bf19d877c4596a8d4`, was identified as malicious by `44/63` VirusTotal security vendors and carried a threat label of `trojan.acao/docdl`, with categories covering trojan, dropper, and downloader activity.

The device action on the alert was `Allowed`, meaning the file was not blocked or quarantined, and Log Management confirmed a successful outbound connection from `172.16.17.56` to `177.53.143.89` over port `443` at the time the alert fired. Although that address returned `0/91` detections on VirusTotal, its Relations tab showed 10+ malicious files communicating with it, including this sample.

The macro itself demonstrated clearly malicious behavior involving obfuscation, Base64 decoding, download-and-execute via `ShellExecute`, self-replication through `Auto_Open`, AV process discovery (`T1518`), sandbox evasion (`T1497`), and bootkit persistence (`T1542.003`).

Based on the strong detection results, malicious behavior, and the confirmed outbound connection to a C2 address associated with the sample, I assessed this alert as a **True Positive**, contained the affected endpoint `Sofia`, and closed the case.
