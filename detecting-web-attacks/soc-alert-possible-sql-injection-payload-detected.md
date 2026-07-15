# SOC Alert Investigation: Possible SQL Injection Payload Detected

<img width="1206" height="246" alt="image" src="https://github.com/user-attachments/assets/1b350a7d-efb6-4cc4-9e8a-c6e36d57ad20" />

Our investigation starts here with a high-severity **LetsDefend SOC Alert: SOC165 - Possible SQL Injection Payload Detected**. This is a Web Attack alert, so I'm going to be looking at suspicious web activity and, according to the rule name, signs of SQL injection. 

To begin the investigation, I've created a case for the alert and I'll work through the provided playbook.

## Playbook Step 1: Understand Why the Alert Was Triggered

The first step of the playbook asks me to understand why the alert was triggered before making any decisions. I'm going to review the requested URL and identify what part of the request matched the detection rule.

<img width="799" height="525" alt="image" src="https://github.com/user-attachments/assets/87deb02a-e4d4-4e93-9741-17cb2d9411fd" />

After expanding the original alert, I've been able to find the following details:

<img width="1029" height="665" alt="image" src="https://github.com/user-attachments/assets/2a3ed79b-f4f5-4464-80af-400c1714e8c9" />

Based on the rule name, this alert appears to be related to a possible SQL Injection attack. The rule name specifically mentioned `Possible SQL Injection Payload Detected`, and the alert trigger reason stated that the requested URL contained `OR 1 = 1`.

The requested URL was:

`https://172.16.17.18/search/?q=%22%20OR%201%20%3D%201%20--%20-`

This URL stood out because the `q` parameter contains URL-encoded SQL injection syntax. When decoded, the payload resembles `" OR 1 = 1 -- -`. The `OR 1=1` condition is commonly associated with SQL Injection attempts because it can be used to force a query condition to always evaluate as true. The `--` sequence is also suspicious because it is commonly used as a SQL comment marker to ignore the rest of a query.

The original alert also shows that the request method was `GET`, which means the activity involved a web request sent to retrieve a resource from a server. This helps identify the traffic as HTTP web traffic and shows that the suspicious activity occurred through the requested URL.

## Playbook Step 2: Collect Data

The next step of the playbook asks me to collect quick context about the traffic so I can better understand what devices and IP addresses are involved. For this step, I’ll review the source and destination information, determine whether the traffic is coming from an external address or from inside the company network, and gather any available ownership or reputation details.

Since this alert involves suspicious web traffic, I’ll focus on identifying the source device, the destination address, and whether the IP or URL has any suspicious reputation indicators.

<img width="944" height="787" alt="image" src="https://github.com/user-attachments/assets/7e4ecc6e-3d85-46d8-a3f5-85787c8d9d1c" />

I started by reviewing the original logs tied to the alert:

<img width="944" height="787" alt="Screenshot 2026-07-14 205810" src="https://github.com/user-attachments/assets/4fc8198b-d057-468e-b34c-44971991ddcc" />

As I can see here, there are 6 events that correlate back to the same source IP address. I'll start by looking at the original log that triggered the alert.

<img width="948" height="785" alt="image" src="https://github.com/user-attachments/assets/2672a055-2969-4de6-a300-1dd7d8fd1a72" />

The event type was listed as `Firewall`, and the device action was `Permitted`, meaning the traffic was allowed rather than blocked.

The log showed traffic from the source address `167.99.169.17` to the destination address `172.16.17.18` over port `443`. The requested URL was:

`https://172.16.17.18/search/?q=%22%20OR%201%20%3D%201%20--%20-`

This URL stood out because the `q` parameter contained URL-encoded SQL injection syntax. When decoded, the payload resembles `" OR 1 = 1 -- -`. The `OR 1=1` condition is commonly associated with SQL Injection attempts because it can force a query condition to evaluate as true. The `--` sequence is also suspicious because it is commonly used as a SQL comment marker to ignore the rest of a query.

Since the alert is related to a possible SQL Injection attack, this request is suspicious because it appears to be testing whether the application’s search parameter is vulnerable to SQL query manipulation.

After investigating the logs that pertained to the alert, I went to investigate both IP addresses in Endpoint Security. However, I was only able to find one IP that pertained to the original alert.

<img width="1155" height="672" alt="image" src="https://github.com/user-attachments/assets/acee8118-a48b-4f90-a852-991addc50775" />

As I can see here, the destination address's endpoint is `172.16.17.18`. The endpoint was identified as `WebServer1001`, which is part of the `letsdefend.local` domain, and operated by the user `webadmin`. The last login time was listed as `Feb, 10, 2022, 11:12 PM`.

As I mentioned above, I couldn't find the source address `167.99.169.17` in Endpoint Security, so I looked it up on VirusTotal because I suspected it was external to the company network.

<img width="1280" height="914" alt="image" src="https://github.com/user-attachments/assets/5a73a903-cff2-4144-8c43-6a34b5d6bb90" />

As I suspected, the IP address associated with the source address was external to the company network. The IP address was associated with `AS14061 DigitalOcean, LLC`, and the country was listed as `US`.

VirusTotal showed that `5/91` security vendors flagged this IP address as malicious. Additional vendors also marked it as suspicious or phishing. The community score was negative at `-15`, and the most recent analysis was listed as `2 days ago`, meaning the reputation data was fairly recent.

While IP reputation alone does not prove malicious activity, the external source address, recent malicious reputation indicators, and the requested URL containing SQL injection syntax support treating this traffic as suspicious.

## Playbook Step 3: Examine HTTP Traffic
The next step of the playbook asks me to examine the HTTP traffic for signs of a web attack. Since this alert is related to a possible SQL Injection attack, I need to review the full HTTP request and look for suspicious values in the URL or request fields.

<img width="796" height="616" alt="image" src="https://github.com/user-attachments/assets/f911062f-24b1-4856-b827-686da44f58c3" />

In this case, the requested URL contains a suspicious payload inside the `q` search parameter:

`https://172.16.17.18/search/?q=%22%20OR%201%20%3D%201%20--%20-`

When decoded, the payload resembles `" OR 1 = 1 -- -`. This stands out because `OR 1=1` is usually associated with a SQL Injection attempt, since it can be used to force a query condition to evaluate as true. The `--` sequence is also suspicious because it is commonly used as a SQL comment marker to ignore the rest of a query.

Because this SQL-like payload was submitted through a search parameter, it suggests that the attacker may have been testing whether the application is vulnerable to SQL query manipulation.

## Playbook Step 4: Is Traffic Malicious?

The next step of the playbook asks me to decide whether the traffic is malicious based on the investigation so far.

<img width="796" height="429" alt="image" src="https://github.com/user-attachments/assets/924ff12d-975e-493b-b1fd-519926872bbf" />

Before making that decision, I’m going to review the related logs and put together a timeline of the activity. There are multiple logs that appear to correlate with this alert at different points in time, so I want to understand how the requests occurred, whether they came from the same source address, and whether the same suspicious SQL-like payload was requested multiple times.

By reviewing the sequence of events, I can better determine whether this was normal web traffic or suspicious activity that may indicate a possible SQL Injection attempt.


To start building the timeline, I reviewed the earliest log I could find from the source address `167.99.169.17` to the destination web server `172.16.17.18`.

<img width="1136" height="688" alt="image" src="https://github.com/user-attachments/assets/0b864b64-7269-4ba2-92ad-a6e02f7c19f1" />

The request method was `GET`, and the device action was listed as `Permitted`, meaning the request was allowed. The server returned HTTP response status `200` with a response size of `3547`, which indicates that the web server successfully responded to the request.

At this point in the timeline, the activity does not appear obviously malicious because the source address only accessed the main page of the web server. However, this event is still useful because it shows earlier activity from the same external source address before the later SQL injection-style payload was observed.


The next related event occurred at `Feb, 25, 2022, 11:32 AM`. The same source address `167.99.169.17` sent another `GET` request to the destination web server `172.16.17.18`.

<img width="1134" height="700" alt="image" src="https://github.com/user-attachments/assets/a1de7af2-635e-4ea8-acd9-17647bee3c11" />

<img width="1134" height="695" alt="image" src="https://github.com/user-attachments/assets/113e80b9-8e07-4823-a87a-730245cc78bd" />

This time, the requested URL was:

`https://172.16.17.18/search/?q=%27`

This request stood out because `%27` URL-decodes to a single quote (`'`). A single quote is commonly used in SQL Injection testing because it can be used to check whether the application properly handles user input in SQL queries.

The request was listed as `Permitted`, but the server returned HTTP response status `500`, which indicates a server-side error. This is suspicious because a SQL injection test payload causing a server error may suggest that the application did not safely handle the input.

At this point in the timeline, the activity appears to move from normal browsing behavior into possible SQL Injection testing.


In the same minute, another related event occurred from the same source address `167.99.169.17` to the destination web server `172.16.17.18`.

<img width="1138" height="689" alt="image" src="https://github.com/user-attachments/assets/ee7e2610-44c6-401e-9566-3121704ff970" />

<img width="1139" height="694" alt="image" src="https://github.com/user-attachments/assets/3de358fd-105b-4aca-ab64-67a1c91dff48" />

This time, the requested URL was:

`https://172.16.17.18/search/?q=%27%20OR%20%271`

This request stood out because the payload appears to build on the previous single quote test. When decoded, the query resembles `' OR '1`, which looks like the beginning of a SQL Injection condition. The use of a single quote followed by `OR` is suspicious because attackers commonly use this pattern to test whether they can manipulate the logic of a SQL query.

The request was listed as `Permitted`, but the server returned HTTP response status `500` with a response size of `948`. This means the server produced an error while still returning a response body. Since this happened after the SQL-like payload was submitted, it supports the possibility that the application did not handle the input safely.

At this point in the timeline, the activity appears to have escalated from a basic single quote test into a more direct SQL Injection-style payload.


A minute later, another related event occurred from the same source address `167.99.169.17` to the destination web server `172.16.17.18`.

<img width="1133" height="693" alt="image" src="https://github.com/user-attachments/assets/e5aaa89b-9585-426d-b94b-7a608b710b20" />

<img width="1136" height="705" alt="image" src="https://github.com/user-attachments/assets/6d6daa54-84cb-43fc-b0df-88b6f8fecbc8" />

This time, the requested URL was:

`https://172.16.17.18/search/?q=%27%20OR%20%27x%27%3D%27x`

This request stood out because the payload appears to be a more complete SQL Injection attempt. When decoded, the query resembles `' OR 'x'='x`, which is suspicious because `'x'='x` is an always-true condition. Attackers commonly use this type of logic to test whether they can manipulate the application’s SQL query and bypass normal query conditions.

The request was listed as `Permitted`, but the server returned HTTP response status `500` with a response size of `948`. This indicates that the server produced an error after receiving the SQL-like payload, which supports treating the activity as suspicious.

At this point in the timeline, the activity had escalated from basic input testing into a more direct SQL Injection-style payload.


Another related event occurred in the same minute from the same source address `167.99.169.17` to the destination web server `172.16.17.18`.

<img width="1132" height="703" alt="image" src="https://github.com/user-attachments/assets/a9e2be4c-d594-4c94-9601-25314c115951" />

<img width="1136" height="695" alt="image" src="https://github.com/user-attachments/assets/842f04ee-be98-4814-9175-06a42a29e4c0" />

This time, the requested URL was:

`https://172.16.17.18/search/?q=1%27%20ORDER%20BY%203--%2B`

This request stood out because the payload included `ORDER BY 3`. When decoded, the query resembles `1' ORDER BY 3--+`, which is commonly associated with SQL Injection testing. Attackers may use `ORDER BY` statements to determine the number of columns returned by the original SQL query.

The `--+` portion is also suspicious because it resembles a SQL comment sequence used to ignore the rest of the query. The request was listed as `Permitted`, but the server returned HTTP response status `500` with a response size of `948`, meaning the server produced an error after receiving the SQL-like payload.

At this point in the timeline, the activity appears to have moved from basic SQL Injection testing into enumeration behavior, where the attacker may have been trying to understand the structure of the SQL query.

Looking at the timeline as a whole, the activity started with normal-looking browsing behavior and then moved into multiple SQL Injection-style payloads submitted through the `q` search parameter. The attacker appeared to start with basic input testing using a single quote, then escalated into more direct SQL-like payloads involving `OR`, always-true conditions, SQL comment syntax, and `ORDER BY` enumeration. The final request was the original request that triggered the SOC alert, and it supports assessing the traffic as malicious.

Based on the evidence reviewed, I assessed the traffic as **Malicious**. The traffic came from an external source IP address, `167.99.169.17`, and targeted the internal web server `172.16.17.18`. The requested URL contained a SQL Injection-style payload inside the `q` parameter:

`https://172.16.17.18/search/?q=%22%20OR%201%20%3D%201%20--%20-`

When decoded, the payload resembles `" OR 1 = 1 -- -`, which is suspicious because `OR 1=1` is commonly used to force a SQL condition to evaluate as true. The `--` sequence is also commonly used as a SQL comment marker to ignore the rest of a query.

In addition, VirusTotal showed that `5/91` security vendors flagged the source IP address as malicious, additional vendors marked it as suspicious or phishing, and the community score was negative. Combined with the repeated SQL Injection-style payloads and the server returning HTTP response status `500` to these requests, the evidence supports treating the traffic as malicious.

Based on this evidence, I selected **Malicious** in the playbook.

## Playbook Step 5: What Is The Attack Type?

The next step of the playbook asks me to identify the attack type based on the malicious traffic observed during the investigation.

<img width="800" height="370" alt="image" src="https://github.com/user-attachments/assets/ce95af31-516c-4eee-a711-0dc6597cc1ed" />

Based on the requested URL and the alert context, I selected **SQL Injection** as the attack type. The request contained a SQL Injection-style payload inside the `q` parameter:

`https://172.16.17.18/search/?q=%22%20OR%201%20%3D%201%20--%20-`

When decoded, the payload resembles `" OR 1 = 1 -- -`. This suggests a possible SQL Injection attempt because the attacker appeared to be submitting SQL-like syntax through the search parameter to test whether the application would pass user input into a SQL query unsafely.

The `OR 1=1` condition is suspicious because it can force a query condition to evaluate as true, and the `--` sequence is commonly used as a SQL comment marker to ignore the rest of a query.

Because the suspicious request involved SQL-like syntax being submitted through a web application parameter, **SQL Injection** was the best description of the attack type from the available options.

## Playbook Step 6: Check if it is a Planned Test

The next step of the playbook asks me to determine whether the malicious traffic may have been part of a planned test or attack simulation. Security testing activity can sometimes trigger alerts, so I am going to check whether there is any evidence that this traffic was expected.

<img width="804" height="549" alt="image" src="https://github.com/user-attachments/assets/112ecd38-f3d9-43c6-92b0-6f75f0b291fc" />

To do this, I will search for related information such as the hostname, username, and IP addresses in the mailbox. I will also review whether the device involved appears to belong to an attack simulation product or testing platform.

<img width="1206" height="717" alt="image" src="https://github.com/user-attachments/assets/19741d29-d593-437f-9f7f-1506f543d4ff" />

<img width="1206" height="715" alt="image" src="https://github.com/user-attachments/assets/69b636d3-7a40-421c-a443-388357d780ef" />

<img width="1206" height="717" alt="image" src="https://github.com/user-attachments/assets/f4ab374d-fb2d-420e-ac36-6b97d4e0f0c2" />

<img width="1204" height="710" alt="image" src="https://github.com/user-attachments/assets/7cadccb4-e01a-4bef-982a-0e9fff3abf97" />

I searched for `172.16.17.18`, `WebServer1001`, and `webadmin`, but no related emails were found. I also searched for the keyword `test` to check whether there were any emails mentioning approved testing activity during 2022, but I did not find any related test notifications.

I also reviewed the device and request details, and I did not find evidence that the traffic was generated by an attack simulation product.

Based on this, I determined that there was no evidence of a planned test, so I selected **Not Planned** in the playbook.

## Playbook Step 7: Determine Direction of Traffic

The next step of the playbook asks me to identify the direction of the malicious traffic.

<img width="798" height="415" alt="image" src="https://github.com/user-attachments/assets/3bcc0446-370d-4061-a273-b56bfa1fbf61" />

Based on the original log, the source address was `167.99.169.17`, which appears to be external to the company network and was associated with `DigitalOcean, LLC`. The destination address was `172.16.17.18`, which belongs to the internal company network.

Because the traffic originated from an external Internet-based source and targeted an internal company web server, I selected **Internet → Company Network**.

## Playbook Step 8: Check Whether the Attack was Successful

The next step of the playbook asks me to determine whether the attack was successful based on the available evidence.

<img width="798" height="696" alt="image" src="https://github.com/user-attachments/assets/ae152882-1f73-4e0c-88da-42927a2d270d" />

I referred back to the original log, and the final log generated by the attacker:

<img width="1136" height="702" alt="image" src="https://github.com/user-attachments/assets/40a1e1ac-716d-4d40-a863-b2e94f0dac65" />

<img width="1136" height="698" alt="image" src="https://github.com/user-attachments/assets/13cf57b8-44da-46a7-b64c-196d2fff6bbf" />

The original alert log showed the SQL Injection-style payload:

`https://172.16.17.18/search/?q=%22%20OR%201%20%3D%201%20--%20-`

When decoded, this resembles `" OR 1 = 1 -- -`, which is a common SQL Injection pattern using an always-true condition and SQL comment syntax.

I also noticed that the other SQL Injection-style requests generated by the attacker returned HTTP response status `500` with the same response size of `948`. A `500` status indicates that the server encountered an internal error after processing the request, which suggests that the application may not have handled the SQL-like input safely.

However, the response sizes were consistent across the SQL Injection-style requests, and I did not find evidence that the server returned database contents or other useful data back to the attacker. Because of this, I determined that the attack was not successful.

## Playbook Step 9: Was the Attack Successful?

The next playbook question asks me to confirm whether the attack was successful based on the previous investigation step.

<img width="798" height="364" alt="image" src="https://github.com/user-attachments/assets/3d5309dd-d061-4d61-bd3c-08aa3cd7800f" />

Based on the HTTP response status of `500` and the consistent response size of `948`, I determined that the attack was not successful. The SQL Injection-style payloads appear to have reached the server and caused errors, but there was no evidence that the attacker extracted data or received useful database output.

Based on this evidence, I selected **No** in the playbook.

## Playbook Step 10: Add Artifacts

<img width="798" height="446" alt="image" src="https://github.com/user-attachments/assets/18ed98a5-b0df-4962-b06e-67b89478c4ec" />

Based on the evidence collected so far, I added the source IP address `167.99.169.17` as an `IP Address` artifact because it was the external address associated with the SQL Injection-style requests against the internal web server.

I also added the related requested URLs as `URL Address` artifacts because they showed the progression of SQL Injection-style testing. The requests started with a URL-encoded single quote, then escalated into `OR` conditions, an always-true condition, `ORDER BY` enumeration, and the final SQL Injection-style payload that triggered the SOC alert.

## Playbook Step 11: Do You Need Tier 2 Escalation?

The next step of the playbook asks me to determine whether Tier 2 escalation is needed. According to the playbook, escalation is required if the attack succeeds or if an internal device is compromised.

<img width="798" height="656" alt="image" src="https://github.com/user-attachments/assets/e770c515-12dc-4627-8ccd-5d8c17fe2010" />

In this case, the attack came from the Internet toward the company network, but the evidence showed that the attack was not successful. The SQL Injection-style requests returned HTTP response status `500` with a consistent response size of `948`, which suggests the server generated errors but did not return useful database output to the attacker.

Because there was no evidence that the attacker extracted data or successfully compromised the internal web server, I selected **No** for Tier 2 escalation.

## Playbook Step 12: Analyst Notes

The next step of the playbook asks me to add analyst notes for the case. I used this section to summarize the main findings from the investigation, including why the traffic looked malicious and whether there was evidence that the attack succeeded.

<img width="798" height="510" alt="image" src="https://github.com/user-attachments/assets/8efe0cdd-e6bb-45a2-9893-58cec5ea7d53" />

Analyst Note: On Feb. 25, 2022, the system detected a possible SQL Injection attempt from the external source IP address 167.99.169.17. The request targeted the internal web server at 172.16.17.18 and used the URL https://172.16.17.18/search/?q=%22%20OR%201%20%3D%201%20--%20-.

During the investigation, I found earlier activity from the same source address leading up to the alert. The activity started with normal-looking browsing behavior, then escalated into multiple SQL Injection-style payloads submitted through the q search parameter. These payloads included a single quote test, OR conditions, an always-true condition, ORDER BY enumeration, and SQL comment syntax.

The source IP address appeared to be external to the company network and was associated with DigitalOcean, LLC. VirusTotal showed multiple vendors flagging the IP address as malicious, with additional vendors marking it as suspicious or phishing.

The SQL Injection-style requests returned HTTP response status 500 with a consistent response size of 948. Based on the consistent response sizes and lack of evidence showing database output or useful data returned to the attacker, I assessed the attack attempt as unsuccessful.

## Playbook Step 13: Finish the Playbook!

The final playbook step was to confirm the investigation and close the case. At this point, I had already added the relevant artifacts, summarized my findings into the analyst notes, and completed all the required playbook actions.

## Final Verdict and Closing Case: True Positive

<img width="598" height="434" alt="image" src="https://github.com/user-attachments/assets/4804bdac-07cc-4e56-ad89-c46cb978054e" />

After completing the playbook, I reviewed the evidence I have collected throughout the investigation to determine whether the alert was a true positive or false positive.

My final verdict is that this alert is a **True Positive**. The traffic appeared malicious because an external source IP address sent multiple web requests to an internal web server using SQL Injection-style payloads inside the `q` search parameter.

The requested URL, `https://172.16.17.18/search/?q=%22%20OR%201%20%3D%201%20--%20-`, strongly suggests a possible SQL Injection attempt. When decoded, the payload resembles `" OR 1 = 1 -- -`, which is suspicious because `OR 1=1` is commonly used to force a SQL condition to evaluate as true, and `--` is commonly used as SQL comment syntax.

Another important detail is that the device action was listed as `Permitted`, meaning the requests were allowed through the security control. However, the attack does not appear to have been successful because the SQL Injection-style requests returned HTTP response status `500` with a consistent response size of `948`. This suggests the server generated errors, but there was no evidence that database contents or useful data were returned to the attacker.

Based on the repeated SQL Injection-style payloads, the external-to-internal traffic direction, the source IP reputation indicators, and the lack of evidence that this was planned testing, I assessed this alert as a **True Positive**.

## Results!!

<img width="1032" height="837" alt="image" src="https://github.com/user-attachments/assets/adbf167a-c275-4c7d-bdc0-49f44906d2ce" />

Hooray, we were able to correctly identify that the URL was a true positive!

## MITRE ATT&CK Framework

Reference: https://attack.mitre.org/techniques/T1190/

This alert maps most closely to **Initial Access - Exploit Public-Facing Application (T1190)**. The traffic came from an external source and targeted a web application endpoint on the internal web server.

The requested URL, `https://172.16.17.18/search/?q=%22%20OR%201%20%3D%201%20--%20-`, contained SQL Injection-style syntax submitted through the `q` search parameter. When decoded, the payload resembles `" OR 1 = 1 -- -`, which suggests an attempt to manipulate the application’s SQL query logic.

SQL Injection is the specific web attack type observed in the alert, while **T1190 - Exploit Public-Facing Application** is the broader MITRE ATT&CK technique that best matches the behavior. Even though the attack does not appear to have successfully returned database contents or useful data, the attacker still attempted to exploit exposed web application functionality.
