# Forensic Files and Notes

A comprehensive repository of forensic evidence collection scripts, tools, and resources for incident response and digital forensics across multiple operating systems.

## 🎯 Repository Goals

This repository serves as a centralised collection of:

- **Cross-platform evidence collection scripts** for Linux, Windows, and macOS
- **Forensic tools and utilities** for incident response
- **Checklists and procedures** for digital forensics
- **Documentation and best practices** for forensic analysis

## 🚀 Current Scripts

### Linux Evidence Collection (`linux_data_collection.sh`) - Version 2.1

- **Advanced incident response** evidence collection for Linux hosts
- **Modern tooling**: Uses AVML for memory capture, `ss` for network connections
- **Comprehensive coverage**: Processes, network, logs, user artifacts, recent executables
- **Security features**: SSH key password protection analysis, file integrity hashing
- **Requirements**: Root privileges, AVML, Linux tools (ss, lsof, etc.)
- **Compatibility**: RHEL and Ubuntu systems

### Windows Evidence Collection (`windows_data_collection.ps1`) - Version 0.1

- **PowerShell-based** evidence collection for Windows systems
- **Administrator privileges** required for comprehensive collection
- **Native Windows tools** with optional Sysinternals integration
- **Comprehensive coverage**: System info, processes, network, user artifacts, logs
- **Best practices**: Follows PowerShell naming conventions and security practices
- **Requirements**: PowerShell 5.1+, Administrator privileges

### Windows Event Log Analyzer (`windows_event_analyzer.ps1`) - Version 0.1Beta

- **Security event log analysis** for Windows systems
- **Anomaly detection**: Identifies process creation events without corresponding logon events
- **Event correlation**: Cross-references Event ID 4688 (Process Creation) with Event ID 4624 (Logon)
- **Multiple output formats**: HTML reports, CSV exports, detailed logging
- **Security focus**: Highlights potential security risks and missing authentication events
- **Requirements**: PowerShell 5.1+, access to security.evtx files

### Static Binary Analyzer (`static_binary_analyzer.py`) - Version 1.0

- **Safe static analysis** of suspicious binary files without execution
- **Cross-platform support**: Analyzes both Windows and Linux executables
- **Multiple analysis tools**: Integrates file, strings, exiftool, objdump, readelf
- **Security indicators**: Identifies suspicious patterns and security concerns
- **VirusTotal integration**: Hash lookup capability with manual URL generation
- **Comprehensive output**: Generates detailed analysis reports in multiple formats
- **Requirements**: Linux system with Python 3.6+, standard Linux tools

### macOS Evidence Collection (`macos_data_collection.sh`) - Version 0.1

- **macOS-specific** evidence collection with security awareness
- **Security protection handling**: SIP, T2 chip, FileVault considerations
- **Unified Logs support**: Basic collection with specialist tooling placeholders
- **Comprehensive coverage**: System info, processes, network, user artifacts
- **Limitations documented**: Memory and disk imaging require specialist tools
- **Requirements**: Root privileges, macOS 10.15+ (Catalina and later)

## 📁 Repository Structure

```bash
ForensicNotes/
├── linux_data_collection.sh      # Linux evidence collection (v2.1)
├── windows_data_collection.ps1   # Windows evidence collection (v0.1)
├── windows_event_analyzer.ps1    # Windows event log analyzer (v0.1Beta)
├── static_binary_analyzer.py     # Static binary analyzer (v1.0)
├── macos_data_collection.sh      # macOS evidence collection (v0.1)
├── old/                          # Legacy scripts and documentation
│   ├── linux_data_collection_V1.sh  # Original Linux script
│   ├── README.md                     # Legacy documentation
│   ├── links.md                      # Useful forensic links
│   ├── JumpDisk-FileList.md          # Jump drive file listings
│   └── ToolList.md                   # Forensic tool recommendations
├── LICENSE                        # Repository license
└── README.md                      # This file
```

## 🔧 Key Features

### Cross-Platform Support

- **Linux**: Full-featured evidence collection with modern tools
- **Windows**: PowerShell-based collection with Sysinternals integration
- **macOS**: Security-aware collection with protection bypass documentation
- **Binary Analysis**: Cross-platform executable analysis (Windows/Linux binaries)

### Evidence Collection Capabilities

- **System Information**: Hardware, OS version, kernel details, filesystems
- **Process Analysis**: Running processes, kernel extensions, launch services
- **Network Forensics**: Active connections, routing, ARP, DNS, firewall rules
- **User Artifacts**: Shell history, SSH configurations, user directories
- **System Logs**: Traditional logs, Unified Logs (macOS), audit logs
- **File Integrity**: SHA256/MD5 hashing of all collected evidence
- **Recent Executables**: Files modified in last 5 days with hashes
- **Binary Analysis**: Static analysis, string extraction, metadata analysis, security indicators

### Security and Compliance

- **Privilege Escalation**: Root/Administrator privileges required
- **Evidence Integrity**: Comprehensive hashing and logging
- **Security Awareness**: Detection of unprotected SSH keys, security risks
- **Audit Trail**: Detailed logging of all collection activities

## 🚨 Limitations and Considerations

### General Limitations

- **Memory Collection**: Requires specialist tooling on all platforms
- **Disk Imaging**: Limited by OS security protections
- **Encrypted Data**: May be inaccessible due to encryption
- **Specialist Tools**: Some evidence requires commercial forensic tools

### Platform-Specific Limitations

- **Linux**: Generally most accessible for forensic collection
- **Windows**: Some areas restricted by Windows security features
- **macOS**: Significant limitations due to SIP, T2 chip, and FileVault

## 📋 Usage Instructions

### Linux

```bash
sudo ./linux_data_collection.sh /path/to/evidence/storage
```

### Windows

```powershell
# Run as Administrator
.\windows_data_collection.ps1 -EvidencePath "D:\evidence"
```

### macOS

```bash
sudo ./macos_data_collection.sh /path/to/evidence/storage
```

### Static Binary Analysis

```bash
python3 static_binary_analyzer.py suspicious_file.exe
python3 static_binary_analyzer.py malware.bin -o /tmp/analysis -v
```

## 🔍 Evidence Output

All scripts generate:

- **Structured evidence directories** with organised file collections
- **Comprehensive hash logs** (SHA256/MD5) for integrity verification
- **Detailed collection logs** with timestamps and status messages
- **Evidence summaries** documenting what was collected and limitations
- **Security risk assessments** (e.g., unprotected SSH keys)

The Static Binary Analyzer additionally generates:

- **Strings analysis** with extracted printable strings
- **Metadata analysis** including file properties and system information
- **Binary structure analysis** with ELF/PE file details
- **Security indicators** highlighting suspicious patterns
- **VirusTotal integration** with hash lookup capabilities

## 🤝 Contributing

This repository welcomes contributions:

- **Bug reports** and feature requests
- **Script improvements** and optimisations
- **Additional platform support**
- **Documentation enhancements**
- **Best practice recommendations**

## 📚 Additional Resources

### Legacy Documentation

- **Tool Lists**: Forensic tool recommendations in `old/ToolList.md`
- **Useful Links**: Forensic resources in `old/links.md`
- **Jump Drive Analysis**: File listing procedures in `old/JumpDisk-FileList.md`

### External Resources

- **AVML**: Linux memory acquisition tool
- **Sysinternals**: Windows system utilities
- **Forensic Toolkits**: Commercial and open-source solutions

## ⚖️ License

This repository is licensed under the terms specified in the `LICENSE` file. Please review the license before using any scripts or tools.

## 🚀 Future Enhancements

### Static Binary Analyzer Roadmap

- **Direct VirusTotal API Integration**: Automated submission and result parsing
- **LLM Analysis Submission**: AI-powered analysis of analysis results
- **Enhanced Malware Detection**: Machine learning-based threat detection
- **Network Behavior Analysis**: Static analysis of network-related code patterns
- **Sandbox Integration**: Safe execution environment for dynamic analysis
- **Threat Intelligence**: Integration with multiple threat intelligence platforms

## ⚠️ Disclaimer

These scripts are designed for **educational and authorised forensic use only**. Users are responsible for:

- **Legal compliance** in their jurisdiction
- **Proper authorisation** before evidence collection
- **Evidence handling** according to forensic best practices
- **Tool validation** before production use

## 📞 Support

For issues, questions, or contributions:

- **Repository Issues**: Use GitHub issue tracking
- **Documentation**: Check script help functions (`--help` flag)
- **Testing**: Scripts include extensive error handling and logging

---

**Note**: This repository represents a work in progress. Scripts are continuously improved based on forensic best practices and user feedback. Always test scripts in a safe environment before production use.
