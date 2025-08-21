# Windows Lateral Movement Techniques

This document summarises lateral movement tactics known on the Windows platform.

## Exploitation of Remote Services (T1210)

**Description:** Adversaries exploit vulnerabilities in remote services or applications to execute code and gain unauthorised access to internal systems.

**How to Hunt:** Look for abnormal activity, logs of remote service exploitation, unusual authentication logs, or known exploitation PoCs. Monitor application/service logs for exploits targeting RDP, SMB, WinRM, etc. Splunk query: 'EventCode=4624 AND LogonType=10'.

---

## Lateral Tool Transfer (T1570)

**Description:** Threat actors transfer tools (e.g., malware, scripts) between compromised hosts to facilitate further attacks.

**How to Hunt:** Monitor file transfer activities to admin shares or remote directories, suspicious use of legitimate tools for file copy, or detection of rare executable artefacts. Sysmon EventID 11 for file creations on network shares is useful.

---

## Remote Service Session Hijacking (T1563)

**Description:** Taking over pre-existing remote service sessions (like RDP, SSH) to move laterally.

**How to Hunt:** Look for session hijack attempts, logon/logoff patterns, duplicate or unusual session IDs in event logs. Check for unexpected logons with the same session credentials.

---

## Remote Services/Authentication Abuses (T1021)

**Description:** Logging into other machines using valid credentials via RDP, SMB/Windows Admin Shares, WinRM, DCOM, VNC, cloud services.

**How to Hunt:** Alert on interactive logons from unexpected accounts or hosts. EventCode=4624 with LogonType=3 (network logon via SMB or DCOM), 10 (RDP), or network authentication events. Correlate with known role-based access.

---

## Use Alternate Authentication Material (T1550)

**Description:** Leveraging stolen password hashes (Pass-the-Hash), Kerberos tickets (Pass-the-Ticket), application tokens, or web cookies to authenticate.

**How to Hunt:** Detect Pass-the-Hash by monitoring for authentication using password hashes, especially without prior user logon. EventCode=4624, 4648; high volume 4648 (Explicit Credential) events without prior 4624. PtT: logons with Kerberos tickets from non-standard or admin hosts.

---

## Internal Spearphishing (T1534)

**Description:** Compromising internal accounts to launch phishing attacks against further targets.

**How to Hunt:** Monitor for suspicious internal mail activity, lookalike domains, or abnormal account use. SIEM rules for unusual mass mail from compromised accounts.

---

## Taint Shared Content (T1080)

**Description:** Delivering malicious code via shared internal storage or files that users are fooled into executing.

**How to Hunt:** Monitor network shares for sudden appearance of unknown executables/scripts. Look for abnormal file modifications or changes in shared folders, Sysmon EventID 11.

---

## Replication Through Removable Media (T1091)

**Description:** Moving malware or data using USB sticks or other removable drives between systems.

**How to Hunt:** Monitor for autorun.inf file creation, logs of device connects/disconnects, execution of binaries from removable media paths.

---

## Software Deployment Tools Abuse (T1072)

**Description:** Compromising enterprise software deployment systems (like SCCM, Intune) for remote execution on large number of hosts.

**How to Hunt:** Monitor configuration changes, unexpected deployments, new package activities, or remote executions initiated by deployment servers.

--
