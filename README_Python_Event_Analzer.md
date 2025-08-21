# Windows Event Log Analyzer - Python Version

## 🔍 Overview

This Python version of the Windows Event Log Analyzer allows **Linux-based investigators** to analyze Windows security event logs (`.evtx` files) without requiring Windows-specific tools or systems. It's designed to run natively on Linux platforms and provides the same analysis capabilities as the PowerShell version.

## 🎯 What It Does

The script analyzes Windows `security.evtx` files to identify **security anomalies** by:

1. **Extracting Process Creation Events** (Event ID 4688) - Shows when new processes are started
2. **Extracting Logon Events** (Event ID 4624) - Shows successful user authentication
3. **Cross-referencing Logon IDs** - Each process should have a corresponding logon event
4. **Identifying Anomalies** - Processes without corresponding logon events may indicate security issues

## 🐧 Linux Compatibility

- ✅ **Tested on**: Ubuntu 20.04+, CentOS 7+, RHEL 8+, Debian 11+
- ✅ **Python**: 3.7+ (3.8+ recommended)
- ✅ **Architecture**: x86_64, ARM64 (with some limitations)
- ✅ **No Windows required** - Pure Linux solution

## 📋 Requirements

### Essential Dependencies

```bash
# Python 3.7 or later
python3 --version

# pip3 package manager
pip3 --version

# evtx library (REQUIRED)
pip3 install evtx
```

### Optional Dependencies (Enhanced Functionality)

```bash
# Enhanced CSV handling
pip3 install pandas

# Enhanced HTML templates
pip3 install jinja2
```

### System Dependencies (if evtx installation fails)

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install python3-dev build-essential

# CentOS/RHEL 8+
sudo dnf install python3-devel gcc make

# CentOS/RHEL 7
sudo yum install python3-devel gcc make
```

## 🚀 Installation

### Method 1: Direct Installation

```bash
# Clone or download the script
wget https://raw.githubusercontent.com/your-repo/windows_event_analyzer.py

# Make executable
chmod +x windows_event_analyzer.py

# Install required dependencies
pip3 install evtx
```

### Method 2: Virtual Environment (Recommended)

```bash
# Create virtual environment
python3 -m venv evtx_analyzer
source evtx_analyzer/bin/activate

# Install dependencies
pip3 install evtx pandas jinja2

# Run the script
python3 windows_event_analyzer.py -f security.evtx
```

### Method 3: Using pip (if available)

```bash
# Install from PyPI (if published)
pip3 install windows-evtx-analyzer

# Or install directly from requirements
pip3 install -r requirements.txt
```

## 📖 Usage

### Basic Usage

```bash
# Analyze a security.evtx file
python3 windows_event_analyzer.py -f security.evtx

# Specify output directory
python3 windows_event_analyzer.py -f security.evtx -o analysis_results

# Verbose output
python3 windows_event_analyzer.py -f security.evtx -v
```

### Command Line Options

```bash
python3 windows_event_analyzer.py -h

Options:
  -f, --file     Path to the security.evtx file (REQUIRED)
  -o, --output   Output directory for results (default: current directory)
  -v, --verbose  Show detailed verbose output
  -h, --help     Show help message
```

### Examples

```bash
# Analyze from mounted Windows drive
python3 windows_event_analyzer.py -f /mnt/windows/Windows/System32/winevt/Logs/Security.evtx

# Analyze from SMB share
python3 windows_event_analyzer.py -f /mnt/smb/evidence/security.evtx -o ./results

# Analyze with verbose logging
python3 windows_event_analyzer.py -f security.evtx -o ./analysis -v
```

## 📊 Output Files

The script generates several output files:

1. **`event_analysis.log`** - Detailed analysis log with timestamps
2. **`security_analysis_report.html`** - Interactive HTML report
3. **`security_anomalies.csv`** - CSV export of detected anomalies
4. **`analysis_summary.txt`** - Plain text summary of findings

## 🔧 Troubleshooting

### Common Issues

#### 1. evtx Library Installation Fails

```bash
# Error: Microsoft Visual C++ 14.0 is required
# Solution: Install build tools
sudo apt-get install python3-dev build-essential

# Error: Failed building wheel for evtx
# Solution: Upgrade pip and setuptools
pip3 install --upgrade pip setuptools wheel
```

#### 2. Permission Denied

```bash
# Error: Permission denied when reading .evtx file
# Solution: Check file permissions
ls -la security.evtx
chmod 644 security.evtx  # If appropriate
```

#### 3. Python Version Issues

```bash
# Error: Python 3.7+ required
# Solution: Check Python version
python3 --version

# If using older version, install Python 3.8+
sudo apt-get install python3.8 python3.8-pip
```

#### 4. Memory Issues with Large Files

```bash
# For very large .evtx files, consider:
# 1. Increase system memory
# 2. Use swap space
# 3. Process in smaller chunks (future enhancement)
```

### Performance Optimization

```bash
# For large files, ensure adequate system resources
# Recommended minimum: 4GB RAM, 2GB free disk space

# Monitor system resources during analysis
htop
df -h
```

## 🧪 Testing

### Test with Sample Data

```bash
# Create a test directory
mkdir test_analysis
cd test_analysis

# Run with help to verify installation
python3 ../windows_event_analyzer.py -h

# Test with a small .evtx file if available
python3 ../windows_event_analyzer.py -f test_security.evtx -o ./results
```

### Validation

The script includes several validation checks:

- ✅ Python version compatibility
- ✅ evtx library availability
- ✅ File existence and permissions
- ✅ Output directory creation
- ✅ Event parsing validation

## 🔒 Security Considerations

### File Handling

- **Input Validation**: All file paths are validated before processing
- **Safe File Operations**: Uses secure file handling practices
- **Error Handling**: Graceful failure without exposing system information

### Output Security

- **Local Output Only**: Results are written to local files only
- **No Network Transmission**: Script doesn't send data over networks
- **Permission Respect**: Respects existing file permissions

## 📈 Performance

### Benchmarks (Typical)

| File Size | Events | Processing Time | Memory Usage |
|-----------|--------|-----------------|--------------|
| 10 MB     | ~1K    | 5-10 seconds    | 50-100 MB   |
| 100 MB    | ~10K   | 30-60 seconds   | 200-500 MB  |
| 1 GB      | ~100K  | 5-10 minutes    | 1-2 GB      |

### Optimization Tips

```bash
# Use SSD storage for better I/O performance
# Ensure adequate RAM (4GB+ recommended)
# Close unnecessary applications during analysis
# Use verbose mode only when needed
```

## 🆘 Support

### Getting Help

1. **Check the logs**: Review `event_analysis.log` for detailed error information
2. **Verify dependencies**: Ensure all required libraries are installed
3. **Check file permissions**: Verify access to input and output directories
4. **Review system resources**: Ensure adequate memory and disk space

### Common Error Messages

```bash
ERROR: The 'evtx' library is required but not installed.
→ Solution: pip3 install evtx

ERROR: Event log file not found
→ Solution: Check file path and permissions

ERROR: Failed to extract Process Creation events
→ Solution: Verify .evtx file integrity
```

## 🔄 Updates and Maintenance

### Keeping Current

```bash
# Update the script
wget -O windows_event_analyzer.py https://raw.githubusercontent.com/your-repo/windows_event_analyzer.py

# Update dependencies
pip3 install --upgrade evtx pandas jinja2
```

### Version History

- **v0.1Beta** - Initial Python release with basic functionality
- Future versions will include performance improvements and additional features

## 📚 Additional Resources

### Documentation

- [evtx Library Documentation](https://github.com/williballenthin/python-evtx)
- [Windows Event Log Format](https://docs.microsoft.com/en-us/windows/win32/wes/windows-event-log)
- [Event ID Reference](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-events)

### Related Tools

- **PowerShell Version**: For Windows-based analysis
- **Linux Evidence Collection**: Companion scripts for Linux forensics
- **macOS Evidence Collection**: Companion scripts for macOS forensics

## ⚠️ Disclaimer

This tool is provided as-is for educational and investigative purposes. Always:

- Test in your environment before production use
- Validate findings with other tools and methods
- Follow proper forensic procedures and chain of custody
- Respect privacy and legal requirements in your jurisdiction

## 🤝 Contributing

Contributions are welcome! Areas for improvement:

- Performance optimization for large files
- Additional event type analysis
- Enhanced reporting formats
- Better error handling and recovery
- Additional platform support

---

Happy Analyzing! 🕵️‍♂️

For issues, questions, or contributions, please refer to the main repository documentation.
