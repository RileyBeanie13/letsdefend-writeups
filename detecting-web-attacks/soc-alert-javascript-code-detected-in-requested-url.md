# SOC Alert Investigation: Javascript Code Detected in Requested URL

<img width="939" height="258" alt="image" src="https://github.com/user-attachments/assets/85ce457d-13bb-450c-807e-270436a20f1f" />

Our investigation starts here with a medium-severity **LetsDefend SOC Alert: SOC166 - Javascript Code Detected in Requested URL**. This is a Web Attack alert, so I'm going to be looking at suspicious web activity and according to the rule name, suspicious URLs. 

To begin the investigation, I've created a case for the alert and I'll work through the provided playbook.

## Playbook Step 1: Understand Why the Alert Was Triggered

The first step of the playbook asks me to understand why the alert was triggered before making any decisions. I'm going to review the requested URL and identify what part of the request matched the detection rule.

<img width="799" height="525" alt="image" src="https://github.com/user-attachments/assets/87deb02a-e4d4-4e93-9741-17cb2d9411fd" />

After expanding the original alert, I've been able to find the following details:

<img width="938" height="666" alt="image" src="https://github.com/user-attachments/assets/676aef43-d187-4148-8062-7a296b9b406b" />

Based on the rule name, this alert was because of JavaScript code being detected in the requested URL. This could point to a possible Cross-Site Scripting attempt, since attacks could place script-like payloads into URL parameters to test whether a web application would reflect or execute their supplied input.

The original alert also shows us that the request method was `GET`, which means the activity involved a web request sent to retrieve a resource from a server. This helps us identify that the traffic being investigated is HTTP web traffic, and that the suspicious activity occurred through the requested URL.

## Playbook Step 2: Collect Data

The next step of the playbook asks me to collect quick context about the traffic so I can better understand what devices and IP addresses are involved. For this step, I’ll review the source and destination information, determine whether the traffic is coming from an external address or from inside the company network, and gather any available ownership or reputation details.

Since this alert involves suspicious web traffic, I’ll focus on identifying the source device, the destination address, and whether the IP or URL has any suspicious reputation indicators.

<img width="800" height="562" alt="image" src="https://github.com/user-attachments/assets/08db5215-aa1f-41eb-a7c2-7c0cd50519bf" />

I started by reviewing the original log tied to the alert.

<img width="1045" height="748" alt="image" src="https://github.com/user-attachments/assets/c1f3aacf-55cd-4128-9e0e-33814710fcd2" />

As I can see here, there are multiple logs from the same source address to the same destination address that correlate with the original alert.

<img width="1045" height="677" alt="image" src="https://github.com/user-attachments/assets/e5f87e2d-d4df-4723-b78d-a286c73e5bb9" />

The original alert that triggered alert had an event type that was listed as `Firewall`, and the device action was `Permitted`, meaning the traffic was allowed rather than blocked.

The log showed traffic from the source address `112.85.42.13` to the destination address `172.16.17.17` over port `443`. The requested URL was:

`https://172.16.17.17/search/?q=<$script>javascript:$alert(1)</script>`

This URL stood out because the `q` parameter contained script-like content. The payload included a modified `<script>` tag and an `alert(1)` style JavaScript function, which are commonly associated with Cross-Site Scripting testing. Since the payload was submitted through a search parameter, this suggests the attacker may have been testing whether the web application reflects or executes user-supplied input.

After investigating the logs that pertained to the alert, I went to investigate both IP addresses in Endpoint Security. However, I was only able to find one IP that pertained to the original alert.

<img width="1061" height="665" alt="image" src="https://github.com/user-attachments/assets/c7206940-cab5-41be-b66e-112a88578088" />

As I can see here, the destination endpoint is `172.16.17.17`. The endpoint was identified as `WebServer1002`, which is part of the `letsdefend.local` domain and is operated by the user `webadmin15`. The last login time was listed as `Feb, 02, 2022, 03:40 PM`.

As I mentioned above, I couldn't find the source address `112.85.42.13` in Endpoint Security, so I looked it up on VirusTotal because I suspected it was external to the company network.

<img width="1193" height="905" alt="image" src="https://github.com/user-attachments/assets/1908dd50-78ab-47c3-ba23-7bf6d3d358ef" />

As I suspected, the IP address associated with the source address was external to the company network. The IP address was associated with `AS4837 CHINA UNICOM China169 Backbone`, and the country was listed as `CN`.

VirusTotal showed that `1/91` security vendor flagged this IP address as malicious, and additional vendors marked it as suspicious. The community score was also negative at `-15`, and the most recent analysis was listed as `6 days ago`, meaning the reputation data was fairly recent.

## Playbook Step 3: Examine HTTP Traffic
The next step of the playbook asks me to examine the HTTP traffic for signs of a web attack. Since this alert is related to a possible Cross-Site Scripting attack, I need to review the full HTTP request and look for suspicious values in the URL or request fields.

<img width="796" height="616" alt="image" src="https://github.com/user-attachments/assets/f911062f-24b1-4856-b827-686da44f58c3" />

In this case, the requested URL contains a script-like payload inside the `q` search parameter. This stands out because the payload includes a modified `<script>` tag and an `alert(1)` style JavaScript function, which are commonly associated with Cross-Site Scripting testing. Since the payload was submitted through a search field, the attacker may be attempting to determine whether the application doesn't properly sanitize it's data and see if it reflects or executes the user's supplied input.

## Playbook Step 4: Is Traffic Malicious?

The next step of the playbook asks me to decide whether the traffic is malicious based on the investigation so far.

<img width="796" height="429" alt="image" src="https://github.com/user-attachments/assets/924ff12d-975e-493b-b1fd-519926872bbf" />

Before making that decision, I’m going to review the related logs and put together a timeline of the activity. There are multiple logs that appear to correlate with this alert at different points in time, so I want to understand how the requests occurred, whether they came from the same source address, and whether the same suspicious URL was requested multiple times.

By reviewing the sequence of events, I can better determine whether this was normal web traffic or suspicious activity that may indicate a possible Cross-Site Scripting attempt.

To start building the timeline, I reviewed the earliest log I could find from the source address `112.85.42.13` to the destination web server `172.16.17.17`.

The first related event occurred on `Feb, 26, 2022, 06:34 PM`, which was about 22 minutes before the alert was triggered. In this event, the source address accessed the base URL:

<img width="1042" height="696" alt="image" src="https://github.com/user-attachments/assets/e652c202-3dd3-4d14-940a-5a19d19449d9" />

The request method was `GET`, and the device action was listed as `Permitted`, meaning the request was allowed. At this point, the request does not appear obviously malicious because it only accessed the main page of the web server and did not include the suspicious JavaScript-like payload.

This event is still useful for the investigation because it shows earlier activity from the same external source address before the suspicious request occurred.

The next related event occurred one minute later at `Feb, 26, 2022, 06:35 PM`. The same source address `112.85.42.13` sent another `GET` request to the same destination web server `172.16.17.17`.

<img width="1044" height="768" alt="image" src="https://github.com/user-attachments/assets/4ced322f-3d7e-4e1b-978e-1aada2162170" />

This time, the requested URL was:

`https://172.16.17.17/about-us/`

The device action was again listed as `Permitted`, meaning the traffic was allowed. At this point, the activity still does not appear obviously malicious because the source address only accessed the `/about-us/` page, which looks like normal web browsing behavior.

However, this event is still useful because it shows continued activity from the same external source address before the suspicious JavaScript-like payload was later observed.

The next event occurred at `Feb, 26, 2022, 06:45 PM`. The same source address `112.85.42.13` sent another `GET` request to the destination web server `172.16.17.17`.

<img width="1046" height="771" alt="image" src="https://github.com/user-attachments/assets/4e573099-9a9b-4881-8260-671994ba20f1" />

<img width="1045" height="770" alt="image" src="https://github.com/user-attachments/assets/a2a903c5-60a3-42c4-a14c-6dd315e46900" />

This time, the requested URL was:

`https://172.16.17.17/search/?q=test`

This stood out because the source address began interacting with the website's search functionality through the `q` parameter. The only value submitted was `test`, so this request, again does not appear malicious by itself. However, we should note this in the timeline because it may show the source testing how the search parameter behaves before submitting a suspicious JavaScript payload.

The request was `Permitted`, and the server returned HTTP response status `200` with a response size of `885`, meaning the server successfully responded to the request.

The next event occurred at `Feb, 26, 2022, 06:46 PM`. The same source address `112.85.42.13` sent another `GET` request to the destination web server `172.16.17.17`.

<img width="1040" height="766" alt="image" src="https://github.com/user-attachments/assets/a6247bb2-5f8e-48d2-bb37-d01a65f14353" />

<img width="1041" height="771" alt="image" src="https://github.com/user-attachments/assets/78870159-f9b3-429b-a4f2-0ecfff8aae3d" />

This time, the requested URL was:

`https://172.16.17.17/search/?q=prompt(8)`

This request stood out because the `q` parameter contained `prompt(8)`, which is JavaScript-like content. Functions such as `prompt()` can be used in Cross-Site Scripting testing to check whether user-supplied input is reflected or executed by the web application.

However, this specific request returned HTTP response status `302` with a response size of `0`. This means the server redirected the request and did not return a response body in this log. Because of that, this event looks suspicious, but it does not clearly show that the payload executed successfully.

This event is still important because it shows the source address moving from a normal search query to JavaScript-like input before the later suspicious payload was observed.

The next event also occurred at `Feb, 26, 2022, 06:46 PM`. The same source address `112.85.42.13` sent another `GET` request to the destination web server `172.16.17.17`.

<img width="1045" height="772" alt="image" src="https://github.com/user-attachments/assets/3d8fd26c-77df-4893-ae3b-9621e0c7b928" />

<img width="1046" height="770" alt="image" src="https://github.com/user-attachments/assets/3e2b8f84-15c2-4a0e-b925-0d07787c1560" />


This time, the requested URL was:

`https://172.16.17.17/search/?q=<$img%20src%20=q%20onerror=prompt(8)$>`

This request stood out because the `q` parameter contained an image tag-style payload with an `onerror` event handler. Decoded, the payload resembles an attempt to use an image tag to trigger `prompt(8)` if the image fails to load. This is suspicious because `onerror` event handlers are commonly used in Cross-Site Scripting payloads to test whether user-supplied input is reflected or executed by the web application.

However, this request returned HTTP response status `302` with a response size of `0`, meaning the server redirected the request and did not return a response body in this log. Because of this, the request is suspicious, but this specific event does not prove that the payload executed successfully.

The next suspicious event occurred at `Feb, 26, 2022, 06:50 PM`. The same source address `112.85.42.13` sent another `GET` request to the destination web server `172.16.17.17`.

<img width="1046" height="764" alt="image" src="https://github.com/user-attachments/assets/3ae17e91-2c04-454e-b99c-01344432245d" />

<img width="1043" height="764" alt="image" src="https://github.com/user-attachments/assets/c2d11ea7-17d3-4865-88d0-2e4bf223e664" />

This time, the requested URL was:

`https://172.16.17.17/search/?q=<$script>$for((i)in(self))eval(i)(1)<$/script>`

This request stood out because the `q` parameter contained a script-like payload using `eval()`. This is suspicious because `eval()` can execute JavaScript code dynamically, and attackers may use it in Cross-Site Scripting payloads to test whether a web application reflects or executes user-supplied input.

However, this request returned HTTP response status `302` with a response size of `0`, meaning the server redirected the request and did not return a response body in this log. Because of this, the request appears malicious, but this specific event does not prove that the payload executed successfully.

The next suspicious event occurred at `Feb, 26, 2022, 06:53 PM`. The same source address `112.85.42.13` sent another `GET` request to the destination web server `172.16.17.17`.

<img width="1046" height="769" alt="image" src="https://github.com/user-attachments/assets/70ea0ec5-d9f3-4d78-8631-ff6164b2f826" />

<img width="1045" height="768" alt="image" src="https://github.com/user-attachments/assets/9e4cf6e6-76dc-4818-8505-9acd2c780af1" />

This time, the requested URL was:

`https://172.16.17.17/search/?q=<$svg><$script%20?>$alert(1)`

This request stood out because the `q` parameter contained an SVG/script-style payload with `alert(1)`. This is suspicious because attackers commonly use payloads involving `script`, `svg`, and `alert(1)` to test whether a web application reflects or executes their supplied input.

However, this request returned HTTP response status `302` with a response size of `0`, meaning the server redirected the request and did not return a response body in this log. Because of this, the request appears malicious, but this specific event does not prove that the payload executed successfully.

The final event in the timeline occurred at `Feb, 26, 2022, 06:56 PM`. This was the original request that triggered the SOC alert. The same source address `112.85.42.13` sent another `GET` request to the destination web server `172.16.17.17`.

<img width="1047" height="768" alt="image" src="https://github.com/user-attachments/assets/656d14ed-febd-42f0-87b7-4fd16812bb57" />

<img width="1045" height="768" alt="image" src="https://github.com/user-attachments/assets/04f89c42-210b-469b-92f1-500c0df1ea64" />

This time, the requested URL was:

`https://172.16.17.17/search/?q=<$script>javascript:$alert(1)</script>`

This request stood out because the `q` parameter contained a script-like payload using `javascript:` and `alert(1)`. This is suspicious because `alert(1)` is commonly used as a basic proof-of-concept payload when testing for Cross-Site Scripting vulnerabilities.

The request was listed as `Permitted`, but it returned HTTP response status `302` with a response size of `0`. This means the server redirected the request and did not return a response body in this log. Because of this, the request appears malicious, but this specific event does not prove that the payload executed successfully.

Looking at the timeline as a whole, the activity started with normal-looking browsing behavior, then it moved into a test search query, and then escalated into multiple JavaScript-like payloads submitted through the search parameter. The final request was the original request that triggered the SOC alert, and it supports assessing the traffic as malicious.

Based on the evidence reviewed, I assessed the traffic as **Malicious**. The traffic came from an external source IP address, `112.85.42.13`, and targeted the internal web server `172.16.17.17`. The requested URL contained a script-like payload inside the `q` parameter:

`https://172.16.17.17/search/?q=<$script>javascript:$alert(1)</script>`

This request is suspicious because `javascript:` and `alert(1)` are commonly associated with Cross-Site Scripting testing. In addition, VirusTotal showed that one security vendor flagged the source IP address as malicious, additional vendors marked it as suspicious, and the community score was negative.

Even though the request returned HTTP response status `302` with a response size of `0`, the repeated JavaScript-like payloads submitted through the search parameter support treating the traffic as malicious. Based on this evidence, I selected **Malicious** in the playbook.

## Playbook Step 5: What is The Attack Type?

The next step of the playbook asks me to identify the attack type based on the malicious traffic observed during the investigation.

<img width="800" height="370" alt="image" src="https://github.com/user-attachments/assets/ce95af31-516c-4eee-a711-0dc6597cc1ed" />

Based on the requested URL and the alert context, I selected **Cross-Site Scripting** as the attack type. The request contained a script-like payload inside the `q` parameter:

`https://172.16.17.17/search/?q=<$script>javascript:$alert(1)</script>`

This suggests a possible Cross-Site Scripting attempt because the attacker appeared to be placing JavaScript-like content into a search parameter to test whether the web application would reflect or execute their supplied input.

Because the suspicious request involved JavaScript-like code being submitted through a web application parameter, **Cross-Site Scripting** was the best description of the attack type from the available options.

## Playbook Step 6: Check if it is a Planned Test

The next step of the playbook asks me to determine whether the malicious traffic may have been part of a planned test or attack simulation. Security testing activity can sometimes trigger alerts, so I am going to check whether there is any evidence that this traffic was expected.

<img width="804" height="549" alt="image" src="https://github.com/user-attachments/assets/112ecd38-f3d9-43c6-92b0-6f75f0b291fc" />

To do this, I will search for related information such as the hostname, username, and IP addresses in the mailbox. I will also review whether the device involved appears to belong to an attack simulation product or testing platform.

I searched the mailbox for the related IP address, hostname, and username to check whether there was any email indicating that this activity was part of planned work or an approved test.

<img width="1125" height="722" alt="image" src="https://github.com/user-attachments/assets/bc84efd8-31a6-45b4-a3ad-3d94a6536ca4" />

<img width="1117" height="839" alt="image" src="https://github.com/user-attachments/assets/2c7cb664-116e-4fad-9f16-983738e113b5" />

<img width="1119" height="715" alt="image" src="https://github.com/user-attachments/assets/1fc481ad-95be-411c-ad07-ee6929fc4cb6" />

<img width="1114" height="715" alt="image" src="https://github.com/user-attachments/assets/041dc2f7-79a8-4b59-afbc-cabeec858ac6" />

I searched for `172.16.17.17`, `WebServer1002`, `webadmin15`, and `112.85.42.13`, but no related emails were found. I also reviewed the device and request details, and I did not find evidence that the traffic was generated by an attack simulation product.

Based on this, I determined that there was no evidence of a planned test, so I selected **Not Planned** in the playbook.

## Playbook Step 7: Determine Direction of Traffic

The next step of the playbook asks me to identify the direction of the malicious traffic.

<img width="798" height="415" alt="image" src="https://github.com/user-attachments/assets/3bcc0446-370d-4061-a273-b56bfa1fbf61" />

Based on the original log, the source address was `112.85.42.13`, which appears to be external to the company network. The destination address was `172.16.17.17`, which belongs to the internal company network and is associated with `WebServer1002`, whereas the source address was based in China.

Because the traffic originated from an external source and targeted an internal company web server, I selected **Internet → Company Network**.

## Playbook Step 8: Check Whether the Attack was Successful

The next step of the playbook asks me to determine whether the attack was successful based on the available evidence.

<img width="798" height="696" alt="image" src="https://github.com/user-attachments/assets/ae152882-1f73-4e0c-88da-42927a2d270d" />

I referred back to the original log, and the final log generated by the attacker:

<img width="1042" height="765" alt="image" src="https://github.com/user-attachments/assets/150c1db9-745e-4993-a01d-d9eed4d88d2a" />

In the original log, the HTTP response status was `302`, which indicates the server redirected the request. The HTTP response size was also `0`, meaning there was no response body returned from the server.

Because the request did not return a response body and there was no clear evidence that the JavaScript-like payload was reflected or executed by the application, I determined that the attack was not successful.

## Playbook Step 9: Was the Attack Successful?

The next playbook question asks me to confirm whether the attack was successful based on the previous investigation step.

<img width="798" height="364" alt="image" src="https://github.com/user-attachments/assets/3d5309dd-d061-4d61-bd3c-08aa3cd7800f" />

Based on the HTTP response status of `302` and the HTTP response size of `0`, I determined that the attack was not successful. The request appears to have reached the server, but there was no evidence that the JavaScript-like payload was reflected or executed by the application.

Based on this evidence, I selected **No** in the playbook.

## Playbook Step 10: Add Artifacts

<img width="798" height="446" alt="image" src="https://github.com/user-attachments/assets/18ed98a5-b0df-4962-b06e-67b89478c4ec" />

Based on the evidence collected so far, I added the requested URL as a `URL Address` artifact because it was the original URL that triggered the SOC alert and contained the JavaScript-like payload.

I also added the source IP address `112.85.42.13` as an `IP Address` artifact because it was the external address associated with the suspicious requests to the internal web server.

## Playbook Step 11: Do You Need Tier 2 Escalation?

The next step of the playbook asks me to determine whether Tier 2 escalation is needed. According to the playbook, escalation is required if the attack succeeds or if an internal device is compromised.

<img width="798" height="656" alt="image" src="https://github.com/user-attachments/assets/e770c515-12dc-4627-8ccd-5d8c17fe2010" />

In this case, the attack came from the Internet toward the company network, but the evidence showed that the attack was not successful. The HTTP response status was `302`, and the response size was `0`, meaning the request was redirected and there was no response body returned in this log.

Because there was no clear evidence that the JavaScript-like payload was reflected or executed by the application, I selected **No** for Tier 2 escalation.

## Playbook Step 12: Analyst Notes

The next step of the playbook asks me to add analyst notes for the case. I used this section to summarize the main findings from the investigation, including why the traffic looked malicious and whether there was evidence that the attack succeeded.

<img width="798" height="510" alt="image" src="https://github.com/user-attachments/assets/8efe0cdd-e6bb-45a2-9893-58cec5ea7d53" />

Analyst Note: On Feb. 26, 2022 at 06:56 PM, the system detected a possible JavaScript Cross-Site Scripting attempt from the external source IP address 112.85.42.13. This request targeted WebServer1002 at 172.16.17.17 and used the URL https://172.16.17.17/search/?q=<$script>javascript:$alert(1)</script>.

During the investigation, I found earlier activity from the same source address leading up to the alert. The activity started with normal-looking browsing behavior, then moved into search parameter testing, and eventually escalated into multiple JavaScript-like payloads submitted through the q parameter.

The source IP address appeared to be external to the company network and was associated with China. VirusTotal showed one vendor flagging the IP as malicious, with additional vendors marking it as suspicious.

The final request returned HTTP response status 302 with a response size of 0. Based on this, there was no clear evidence that the JavaScript-like payload was reflected or executed by the application, so I assessed the attack attempt as unsuccessful.

## Playbook Step 13: Finish the Playbook!

The final playbook step was to confirm the investigation and close the case. At this point, I had already added the relevant artifacts, summarized my findings into the analyst notes, and completed all the required playbook actions.

<img width="798" height="346" alt="image" src="https://github.com/user-attachments/assets/2ca1432f-4944-4122-9d64-f2575b3cd889" />

## Final Verdict and Closing Case: True Positive

<img width="597" height="432" alt="image" src="https://github.com/user-attachments/assets/a01cb4e6-bb90-4567-ab81-7787fcef7ebb" />

After completing the playbook, I reviewed the evidence I have collected throughout the investigation to determine whether the alert was a true positive or false positive.

My final verdict is that this alert is a **True Positive**. The traffic appeared malicious because an external source IP address sent multiple web requests to an internal web server and eventually submitted a JavaScript-like payload through the search parameter. Additionally, the source IP address was flagged as malicious by one security vendor, and suspicious by other ones.

The requested URL, `https://172.16.17.17/search/?q=<$script>javascript:$alert(1)</script>`, strongly suggests a possible Cross-Site Scripting attempt. The use of `javascript:` and `alert(1)` is suspicious because these are commonly associated with XSS testing, where an attacker checks whether a web application will reflect or execute user-supplied input.

Another important detail is that the device action was listed as `Permitted`, meaning the request was allowed through the security control. However, the attack does not appear to have been successful because the HTTP response status was `302` and the response size was `0`, meaning the request was redirected and there was no clear evidence that the payload was reflected or executed by the application.

Based on the JavaScript-like payload, the repeated suspicious requests through the search parameter, the external-to-internal traffic direction, and the source IP reputation indicators, I assessed this alert as a **True Positive**.

## Results!!

<img width="943" height="837" alt="image" src="https://github.com/user-attachments/assets/d05b8c99-a7e6-4698-bcba-57d19e5a4bdd" />

Hooray, we were able to correctly identify that the URL was a true positive!

## MITRE ATT&CK Framework

Reference: https://attack.mitre.org/techniques/T1190/

This alert maps most closely to **Initial Access - Exploit Public-Facing Application (T1190)**. The traffic came from an external source and targeted a web application endpoint on the internal web server.

The requested URL, `https://172.16.17.17/search/?q=<$script>javascript:$alert(1)</script>`, contained JavaScript-like content submitted through the search parameter. This suggests a possible Cross-Site Scripting attempt, where an attacker may try to abuse a web application by getting it to reflect or execute user-supplied input.

Cross-Site Scripting is the specific web attack type observed in the alert, while **T1190 - Exploit Public-Facing Application** is the broader MITRE ATT&CK technique that best matches the behavior.
