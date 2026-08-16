# SOC Alert Investigation: Requested T.I. URL Address

<img width="1013" height="206" alt="image" src="https://github.com/user-attachments/assets/d351ee94-07e0-4f2a-8859-1d88876e7861" />

Our investigation starts here with a high-severity **LetsDefend SOC Alert: SOC105 - Requested T.I. URL Address**. This is a **ThreatIntel** alert, so I'm going to be looking at the requested URL, its reputation across threat intel sources, which host made the request, and whether the connection succeeded or was blocked.

To begin the investigation, I've created a case for the alert and I'll work through the provided playbook.


## Playbook Step 1: Analyze Threat Intel Data

The first step of the playbook asks me to analyze the threat intel data by checking the URL, IP address, domain, or hash against third-party sandboxes and reputation services, then classifying it as either malicious or non-malicious.

For this step, I'm going to take the URL from the alert and run it through third-party reputation and sandbox services to determine whether the indicator is genuinely malicious or a false positive from the threat intel feed. The playbook recommends VirusTotal, URLScan, URLhaus, ANY.RUN, and Hybrid Analysis, and I'll use whichever of them are needed to reach a confident verdict.

<img width="797" height="469" alt="image" src="https://github.com/user-attachments/assets/6b1f5538-0b0a-4e89-91a4-a426089274c3" />

After expanding the alert, I identified the main details tied to the detection. The alert involved the host `MarksPhone` with the source address `10.15.15.12`, under the username `Mark`. The requested URL was `https://bit.ly/TAPSCAN`, resolving to the destination address `67.199.248.10` with the destination hostname `bit.ly`. The user agent was a Chrome browser string, and the alert was mapped to `T1566` (Phishing) with a device action of `Allowed`, meaning the request was not blocked.

First I started my investigation with VirusTotal.

<img width="1261" height="911" alt="image" src="https://github.com/user-attachments/assets/f1d17e47-eba2-49ca-a306-cbe8953c0d78" />

The URL returned a `2/92` detection rate with a community score of `-1`. The vendor categories were `computersandsoftware`, `information technology`, `web hosting`, and `marketing & merchandising`, with no vendor categorizing it as phishing or malware. The URL returned an HTTP 200 with `text/html` content and tags for trackers and third-party cookies, and it was first submitted in April 2020 and still resolving, which is unusual for genuinely malicious infrastructure.

I then checked `bit.ly` itself.

<img width="1261" height="911" alt="image" src="https://github.com/user-attachments/assets/db07d1de-8544-4fc2-ba27-5d88aebbb2a9" />

`bit.ly` is a legitimate and widely used URL shortening service. That alone does not clear the indicator, since shorteners are commonly abused to hide malicious destinations, so the actual redirect target still needed to be confirmed.

<img width="1260" height="781" alt="image" src="https://github.com/user-attachments/assets/6b9fa307-8a82-4d24-8179-81471ed60157" />

To see where the link resolved without visiting it directly, I ran it through URLScan.io. URLScan returned a verdict of "No classification" and Google Safe Browsing also returned no classification. The Page URL History showed the full redirect chain: `https://bit.ly/TAPSCAN` returned a 301 to `redirect.appmetrica.yandex.com`, which returned a 302 to a Google Play Store listing for `pdf.tap.scanner`. The scan showed 85 requests across Google-owned infrastructure over HTTPS, with detected technologies including Google Analytics, Google Tag Manager, DoubleClick, and reCAPTCHA.

<img width="1260" height="914" alt="image" src="https://github.com/user-attachments/assets/1813cc63-fcb8-4d10-9707-8e0025c992df" />

Finally, I confirmed the destination, which was the official Google Play Store page for "PDF Scanner app - TapScanner" by Tap AI, an application with over 100 million downloads and 2.91 million reviews.

The full redirect chain is a standard mobile app install campaign, where a shortened link routes through an analytics service that tracks the click before redirecting to a Google Play Store listing. Since the destination is a legitimate application on an official app store, I classified this indicator as **Non-malicious**.


## Playbook Step 2: Add Artifacts

The next step of the playbook asks me to add the relevant indicators collected during the investigation as artifacts.

<img width="798" height="446" alt="image" src="https://github.com/user-attachments/assets/18ed98a5-b0df-4962-b06e-67b89478c4ec" />

I added the following artifacts:

- **IP Address:** `10.15.15.12`  
  Internal IP address of the affected endpoint `MarksPhone`, used by the user Mark.

- **URL Address:** `https://bit.ly/TAPSCAN`  
  Shortened URL requested by the endpoint that triggered the threat intel match. The link redirects through `redirect.appmetrica.yandex.com` to a Google Play Store listing for `pdf.tap.scanner`. VirusTotal returned `2/92` detections and URLScan returned no classification.


## Playbook Step 3: Analyst Notes

The next step of the playbook asks me to add analyst notes for the case. I used this section to summarize the main findings from the investigation, including the flagged URL, the redirect chain, and the analysis results that supported the verdict.

<img width="798" height="510" alt="image" src="https://github.com/user-attachments/assets/8efe0cdd-e6bb-45a2-9893-58cec5ea7d53" />

**Analyst Note:** On `Mar. 7, 2021, at 17:47`, the system flagged a threat intel match on the URL `https://bit.ly/TAPSCAN`, requested by the internal endpoint `MarksPhone` at `10.15.15.12` under the user Mark. The device action was listed as `Allowed`, meaning the request was not blocked.

The request originated from a Chrome user agent on a mobile device, consistent with normal user browsing rather than automated or scripted activity.

VirusTotal returned a `2/92` detection rate with a community score of `-1`. Vendor categories included `computersandsoftware`, `information technology`, and `marketing & merchandising`, with no vendor categorizing the URL as phishing or malware. The URL returned an HTTP 200 and has been resolving since its first submission in April 2020.

URLScan.io returned no classification, and Google Safe Browsing also returned no classification. The Page URL History showed the full redirect chain: `bit.ly/TAPSCAN` returned a 301 to `redirect.appmetrica.yandex.com`, which returned a 302 to a Google Play Store listing for `pdf.tap.scanner`. The destination was confirmed as the official Play Store page for "PDF Scanner app - TapScanner" by Tap AI, an application with over 100 million downloads.

The full redirect chain is a standard mobile app install campaign, where a shortened link routes through an analytics service that tracks the click before redirecting to a Google Play Store listing. Since the destination is a legitimate application on an official app store, I assessed this indicator as non-malicious. No further action was required beyond documenting the finding.


## Playbook Step 4: Review and Submit

The final playbook step was to confirm the investigation and close the case. At this point, I had already classified the threat intel data, added the relevant artifacts, and summarized my findings into the analyst notes, so the remaining step was to select the final verdict and submit.

<img width="800" height="374" alt="image" src="https://github.com/user-attachments/assets/0a43da4d-df43-4fd9-8a0e-0e7655fe0310" />

Since the URL resolved to a legitimate application on the official Google Play Store and no service flagged the destination as malicious, I selected **False Positive** and closed the case.

## Results!!

<img width="957" height="447" alt="image" src="https://github.com/user-attachments/assets/45720dc4-0855-4d19-811c-06294286fffa" />

Hooray! We correctly to identified the alert was a false positive!
