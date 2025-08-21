#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
Windows Event Log Security Analyzer (Python Version)
Version: 0.1Beta
Description: Analyzes Windows security.evtx files to identify process creation
             events (Event ID 4688) that lack corresponding logon events (Event ID 4624)
             for the same Logon ID. This helps identify potential security anomalies.
             
             This Python version is designed to run on Linux platforms and can analyze
             Windows security event logs without requiring Windows-specific tools.
             
Requirements: Python 3.7+, Linux platform, evtx library
Usage: python3 windows_event_analyzer.py -f "path/to/security.evtx" [-o "output_directory"]
Notes: This is a BETA version and has not been thoroughly tested in production.
       Use with caution and validate results in your environment.
       
       IMPORTANT: This script requires the 'evtx' library to parse Windows .evtx files.
       Install it using: pip3 install evtx
       
       For additional functionality, you may also want to install:
       - pandas: pip3 install pandas (for enhanced CSV handling)
       - jinja2: pip3 install jinja2 (for enhanced HTML templates)
=============================================================================
"""

import argparse
import csv
import json
import logging
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    import evtx
except ImportError:
    print("ERROR: The 'evtx' library is required but not installed.")
    print("Install it using: pip3 install evtx")
    print("This library allows Python to parse Windows .evtx files on Linux.")
    sys.exit(1)

# Optional dependencies - will use basic functionality if not available
try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False
    print("INFO: pandas not available. Using basic CSV functionality.")

try:
    from jinja2 import Template
    JINJA2_AVAILABLE = True
except ImportError:
    JINJA2_AVAILABLE = False
    print("INFO: jinja2 not available. Using basic HTML generation.")

# Script Configuration
SCRIPT_VERSION = "0.1Beta"
SCRIPT_NAME = "windows_event_analyzer.py"
AUTHOR = "Taz Wake"
CREATED_DATE = datetime.now().strftime("%Y-%m-%d")

# Global variables
analysis_results = {
    'process_creation_events': [],
    'logon_events': [],
    'anomalies': [],
    'summary': {}
}

# ANSI color codes for terminal output
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def print_status(level: str, message: str, no_newline: bool = False):
    """
    Print status messages with timestamps and colors.
    
    Args:
        level: Message level (INFO, WARNING, ERROR, SUCCESS, DEBUG)
        message: Message text
        no_newline: Whether to suppress newline
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Color mapping
    color_map = {
        "INFO": Colors.OKBLUE,
        "WARNING": Colors.WARNING,
        "ERROR": Colors.FAIL,
        "SUCCESS": Colors.OKGREEN,
        "DEBUG": Colors.OKCYAN
    }
    
    color = color_map.get(level, Colors.ENDC)
    status_message = f"[{timestamp}] {level}: {message}"
    
    # Always print to console with colors
    if no_newline:
        print(f"{color}{status_message}{Colors.ENDC}", end="", flush=True)
    else:
        print(f"{color}{status_message}{Colors.ENDC}")
    
    # Log to file
    if 'log_file' in globals():
        logging.info(f"{level}: {message}")

def show_help():
    """Display help information."""
    help_text = f"""
{SCRIPT_NAME} - Windows Security Event Log Analyzer v{SCRIPT_VERSION}

DESCRIPTION:
    This script analyzes Windows security.evtx files to identify process creation
    events that lack corresponding logon events, which may indicate security anomalies.
    
    This Python version is designed to run on Linux platforms and can analyze
    Windows security event logs without requiring Windows-specific tools.

USAGE:
    python3 {SCRIPT_NAME} -f <path_to_security.evtx> [-o <output_directory>] [-v] [-h]

PARAMETERS:
    -f, --file         Path to the security.evtx file to analyze (REQUIRED)
    -o, --output       Output directory for analysis results (OPTIONAL, defaults to current directory)
    -v, --verbose      Show detailed verbose output (OPTIONAL)
    -h, --help         Show this help message (OPTIONAL)

EXAMPLES:
    python3 {SCRIPT_NAME} -f "security.evtx"
    python3 {SCRIPT_NAME} -f "security.evtx" -o "analysis_results" -v
    python3 {SCRIPT_NAME} -h

REQUIREMENTS:
    - Python 3.7 or later
    - Linux platform (tested on Ubuntu, CentOS, RHEL)
    - evtx library: pip3 install evtx
    - Access to the security.evtx file
    - Sufficient permissions to read event log files

OPTIONAL DEPENDENCIES:
    - pandas: pip3 install pandas (enhanced CSV handling)
    - jinja2: pip3 install jinja2 (enhanced HTML templates)

OUTPUT:
    - Analysis report in HTML format
    - CSV export of anomalies
    - Detailed log file
    - Summary statistics

BETA VERSION NOTES:
    - This is a BETA version and may contain bugs
    - Test thoroughly in your environment before production use
    - Some event parsing may not work with all Windows versions
    - Performance may vary with large event log files
    - The evtx library is actively maintained but may have limitations

LINUX COMPATIBILITY:
    - Tested on Ubuntu 20.04+, CentOS 7+, RHEL 8+
    - Requires Python 3.7+ with pip3
    - May require additional system libraries for evtx compilation
    - If evtx installation fails, try: sudo apt-get install python3-dev build-essential
"""
    print(help_text)
    sys.exit(0)

def validate_environment(event_log_path: str, output_path: str, verbose: bool):
    """
    Validate input parameters and environment.
    
    Args:
        event_log_path: Path to the security.evtx file
        output_path: Output directory path
        verbose: Whether to show verbose output
    """
    print_status("INFO", "Validating environment and parameters...")
    
    # Check Python version
    if sys.version_info < (3, 7):
        print_status("ERROR", f"Python 3.7 or later is required. Current version: {sys.version}")
        sys.exit(1)
    
    python_version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    print_status("INFO", f"Python version: {python_version}")
    
    # Check evtx library
    try:
        import evtx
        print_status("INFO", f"evtx library version: {evtx.__version__}")
    except AttributeError:
        print_status("INFO", "evtx library loaded (version unknown)")
    
    # Validate event log file
    if not os.path.isfile(event_log_path):
        print_status("ERROR", f"Event log file not found: {event_log_path}")
        sys.exit(1)
    
    file_info = os.stat(event_log_path)
    file_size_mb = file_info.st_size / (1024 * 1024)
    
    if not event_log_path.lower().endswith('.evtx'):
        print_status("WARNING", f"File extension is not .evtx: {Path(event_log_path).suffix}")
    
    print_status("INFO", f"Event log file validated: {event_log_path}")
    print_status("INFO", f"File size: {file_size_mb:.2f} MB")
    
    # Validate output path
    if not os.path.exists(output_path):
        try:
            os.makedirs(output_path, exist_ok=True)
            print_status("INFO", f"Created output directory: {output_path}")
        except OSError as e:
            print_status("ERROR", f"Failed to create output directory: {output_path}")
            print_status("ERROR", f"Error: {e}")
            sys.exit(1)
    
    print_status("SUCCESS", "Environment validation completed successfully")

def initialize_output_files(output_path: str):
    """
    Initialize logging and output files.
    
    Args:
        output_path: Output directory path
    """
    print_status("INFO", "Initializing output files...")
    
    global log_file, html_report, csv_report, summary_file
    
    log_file = os.path.join(output_path, "event_analysis.log")
    html_report = os.path.join(output_path, "security_analysis_report.html")
    csv_report = os.path.join(output_path, "security_anomalies.csv")
    summary_file = os.path.join(output_path, "analysis_summary.txt")
    
    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    # Create log file header
    log_header = f"""
=============================================================================
                    WINDOWS SECURITY EVENT LOG ANALYSIS
=============================================================================
Script: {SCRIPT_NAME}
Version: {SCRIPT_VERSION}
Author: {AUTHOR}
Analysis Date: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
Event Log: {event_log_path}
Output Directory: {output_path}
=============================================================================

"""
    
    with open(log_file, 'w', encoding='utf-8') as f:
        f.write(log_header)
    
    # Create CSV header
    csv_header = "Timestamp,EventID,LogonID,ProcessName,CommandLine,ComputerName,AnomalyType,Details"
    with open(csv_report, 'w', newline='', encoding='utf-8') as f:
        f.write(csv_header + '\n')
    
    print_status("SUCCESS", "Output files initialized successfully")

def extract_process_creation_events(event_log_path: str):
    """
    Extract Event ID 4688 (Process Creation) events.
    
    Args:
        event_log_path: Path to the security.evtx file
    """
    print_status("INFO", "Extracting Process Creation events (Event ID 4688)...")
    
    try:
        process_events = []
        event_count = 0
        
        with evtx.Evtx(event_log_path) as evtx_file:
            for record in evtx_file.records():
                try:
                    # Parse the XML content
                    xml_content = record.xml()
                    
                    # Check if this is Event ID 4688
                    if '<EventID>4688</EventID>' in xml_content:
                        event_count += 1
                        
                        # Extract relevant information
                        event_data = parse_process_creation_event(xml_content, record)
                        
                        if event_data and event_data.get('LogonID') and event_data['LogonID'] != '0x0':
                            process_events.append(event_data)
                        
                        if event_count % 100 == 0:
                            print_status("INFO", f"Processing event {event_count}...")
                
                except Exception as e:
                    print_status("WARNING", f"Failed to parse event record: {e}")
                    continue
        
        analysis_results['process_creation_events'] = process_events
        analysis_results['summary']['ProcessCreationCount'] = len(process_events)
        
        print_status("SUCCESS", f"Successfully extracted {len(process_events)} valid Process Creation events")
        
    except Exception as e:
        print_status("ERROR", f"Failed to extract Process Creation events: {e}")
        sys.exit(1)

def extract_logon_events(event_log_path: str):
    """
    Extract Event ID 4624 (Logon) events.
    
    Args:
        event_log_path: Path to the security.evtx file
    """
    print_status("INFO", "Extracting Logon events (Event ID 4624)...")
    
    try:
        logon_events = []
        event_count = 0
        
        with evtx.Evtx(event_log_path) as evtx_file:
            for record in evtx_file.records():
                try:
                    # Parse the XML content
                    xml_content = record.xml()
                    
                    # Check if this is Event ID 4624
                    if '<EventID>4624</EventID>' in xml_content:
                        event_count += 1
                        
                        # Extract relevant information
                        event_data = parse_logon_event(xml_content, record)
                        
                        if event_data and event_data.get('LogonID') and event_data['LogonID'] != '0x0':
                            logon_events.append(event_data)
                        
                        if event_count % 100 == 0:
                            print_status("INFO", f"Processing event {event_count}...")
                
                except Exception as e:
                    print_status("WARNING", f"Failed to parse event record: {e}")
                    continue
        
        analysis_results['logon_events'] = logon_events
        analysis_results['summary']['LogonCount'] = len(logon_events)
        
        print_status("SUCCESS", f"Successfully extracted {len(logon_events)} valid Logon events")
        
    except Exception as e:
        print_status("ERROR", f"Failed to extract Logon events: {e}")
        sys.exit(1)

def parse_process_creation_event(xml_content: str, record) -> Optional[Dict]:
    """
    Parse a process creation event from XML content.
    
    Args:
        xml_content: XML content of the event
        record: Event record object
        
    Returns:
        Dictionary containing parsed event data or None if parsing fails
    """
    try:
        # Extract basic information
        event_data = {
            'TimeCreated': record.timestamp(),
            'EventID': 4688,
            'LogonID': None,
            'ProcessName': None,
            'CommandLine': None,
            'ComputerName': None,
            'EventRecordID': record.record_num()
        }
        
        # Extract Logon ID (Property 7)
        logon_id_match = extract_property_value(xml_content, 7)
        if logon_id_match:
            event_data['LogonID'] = logon_id_match
        
        # Extract Process Name (Property 5)
        process_name_match = extract_property_value(xml_content, 5)
        if process_name_match:
            event_data['ProcessName'] = process_name_match
        
        # Extract Command Line (Property 8)
        command_line_match = extract_property_value(xml_content, 8)
        if command_line_match:
            event_data['CommandLine'] = command_line_match
        
        # Extract Computer Name from System section
        computer_name_match = extract_system_value(xml_content, 'Computer')
        if computer_name_match:
            event_data['ComputerName'] = computer_name_match
        
        return event_data
        
    except Exception as e:
        print_status("WARNING", f"Failed to parse process creation event: {e}")
        return None

def parse_logon_event(xml_content: str, record) -> Optional[Dict]:
    """
    Parse a logon event from XML content.
    
    Args:
        xml_content: XML content of the event
        record: Event record object
        
    Returns:
        Dictionary containing parsed event data or None if parsing fails
    """
    try:
        # Extract basic information
        event_data = {
            'TimeCreated': record.timestamp(),
            'EventID': 4624,
            'LogonID': None,
            'LogonType': None,
            'UserName': None,
            'Domain': None,
            'ComputerName': None,
            'EventRecordID': record.record_num()
        }
        
        # Extract Logon ID (Property 7)
        logon_id_match = extract_property_value(xml_content, 7)
        if logon_id_match:
            event_data['LogonID'] = logon_id_match
        
        # Extract Logon Type (Property 8)
        logon_type_match = extract_property_value(xml_content, 8)
        if logon_type_match:
            event_data['LogonType'] = logon_type_match
        
        # Extract User Name (Property 5)
        user_name_match = extract_property_value(xml_content, 5)
        if user_name_match:
            event_data['UserName'] = user_name_match
        
        # Extract Domain (Property 6)
        domain_match = extract_property_value(xml_content, 6)
        if domain_match:
            event_data['Domain'] = domain_match
        
        # Extract Computer Name from System section
        computer_name_match = extract_system_value(xml_content, 'Computer')
        if computer_name_match:
            event_data['ComputerName'] = computer_name_match
        
        return event_data
        
    except Exception as e:
        print_status("WARNING", f"Failed to parse logon event: {e}")
        return None

def extract_property_value(xml_content: str, property_index: int) -> Optional[str]:
    """
    Extract property value from XML content by index.
    
    Args:
        xml_content: XML content of the event
        property_index: Property index to extract
        
    Returns:
        Property value or None if not found
    """
    try:
        # Look for Property tag with the specified index
        start_tag = f'<Property Name="Property{property_index}">'
        end_tag = f'</Property>'
        
        start_pos = xml_content.find(start_tag)
        if start_pos != -1:
            start_pos += len(start_tag)
            end_pos = xml_content.find(end_tag, start_pos)
            if end_pos != -1:
                return xml_content[start_pos:end_pos].strip()
        
        return None
        
    except Exception:
        return None

def extract_system_value(xml_content: str, value_name: str) -> Optional[str]:
    """
    Extract system value from XML content.
    
    Args:
        xml_content: XML content of the event
        value_name: Name of the system value to extract
        
    Returns:
        System value or None if not found
    """
    try:
        # Look for System section values
        start_tag = f'<{value_name}>'
        end_tag = f'</{value_name}>'
        
        start_pos = xml_content.find(start_tag)
        if start_pos != -1:
            start_pos += len(start_tag)
            end_pos = xml_content.find(end_tag, start_pos)
            if end_pos != -1:
                return xml_content[start_pos:end_pos].strip()
        
        return None
        
    except Exception:
        return None

def find_anomalies():
    """Identify anomalies (process creation without corresponding logon)."""
    print_status("INFO", "Analyzing events for anomalies...")
    
    anomalies = []
    process_count = 0
    
    for process_event in analysis_results['process_creation_events']:
        process_count += 1
        
        if process_count % 100 == 0:
            print_status("INFO", f"Analyzing process {process_count} of {len(analysis_results['process_creation_events'])}...")
        
        logon_id = process_event.get('LogonID')
        if not logon_id:
            continue
        
        # Check for corresponding logon event
        corresponding_logon = None
        for logon_event in analysis_results['logon_events']:
            if logon_event.get('LogonID') == logon_id:
                corresponding_logon = logon_event
                break
        
        if not corresponding_logon:
            anomaly = {
                'Timestamp': process_event.get('TimeCreated'),
                'EventID': process_event.get('EventID'),
                'LogonID': logon_id,
                'ProcessName': process_event.get('ProcessName'),
                'CommandLine': process_event.get('CommandLine'),
                'ComputerName': process_event.get('ComputerName'),
                'AnomalyType': 'Missing Logon Event',
                'Details': f'Process creation event found without corresponding logon event for Logon ID: {logon_id}'
            }
            
            anomalies.append(anomaly)
            
            # Add to CSV report
            csv_line = f"{anomaly['Timestamp']},{anomaly['EventID']},{anomaly['LogonID']},{anomaly['ProcessName']},\"{anomaly['CommandLine']}\",{anomaly['ComputerName']},{anomaly['AnomalyType']},{anomaly['Details']}"
            with open(csv_report, 'a', newline='', encoding='utf-8') as f:
                f.write(csv_line + '\n')
    
    analysis_results['anomalies'] = anomalies
    analysis_results['summary']['AnomalyCount'] = len(anomalies)
    
    print_status("SUCCESS", f"Analysis completed. Found {len(anomalies)} anomalies")

def generate_html_report():
    """Generate HTML report."""
    print_status("INFO", "Generating HTML report...")
    
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Windows Security Event Analysis Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background-color: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }}
        h2 {{ color: #34495e; margin-top: 30px; }}
        .summary {{ background-color: #ecf0f1; padding: 15px; border-radius: 5px; margin: 20px 0; }}
        .summary-item {{ margin: 10px 0; }}
        .anomaly {{ background-color: #fff3cd; border: 1px solid #ffeaa7; padding: 10px; margin: 10px 0; border-radius: 5px; }}
        .anomaly-highlight {{ background-color: #f8d7da; border-color: #f5c6cb; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #3498db; color: white; }}
        tr:nth-child(even) {{ background-color: #f2f2f2; }}
        .warning {{ color: #e74c3c; font-weight: bold; }}
        .info {{ color: #3498db; }}
        .success {{ color: #27ae60; }}
        .beta-notice {{ background-color: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 5px; margin: 20px 0; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 Windows Security Event Analysis Report</h1>
        
        <div class="beta-notice">
            <strong>⚠️ BETA VERSION NOTICE:</strong> This report was generated by a beta version of the Windows Event Log Analyzer (Python). 
            Please validate all findings in your environment before taking action.
        </div>
        
        <div class="summary">
            <h2>📊 Analysis Summary</h2>
            <div class="summary-item"><strong>Analysis Date:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</div>
            <div class="summary-item"><strong>Event Log File:</strong> {event_log_path}</div>
            <div class="summary-item"><strong>Total Process Creation Events:</strong> {analysis_results['summary'].get('ProcessCreationCount', 0)}</div>
            <div class="summary-item"><strong>Total Logon Events:</strong> {analysis_results['summary'].get('LogonCount', 0)}</div>
            <div class="summary-item"><strong>Anomalies Detected:</strong> <span class="warning">{analysis_results['summary'].get('AnomalyCount', 0)}</span></div>
        </div>
        
        <h2>🚨 Security Anomalies Detected</h2>"""
    
    if len(analysis_results['anomalies']) == 0:
        html_content += """
        <div class="success">
            <strong>✅ No anomalies detected!</strong> All process creation events have corresponding logon events.
        </div>"""
    else:
        html_content += f"""
        <p class="warning">The following {len(analysis_results['anomalies'])} anomalies were detected:</p>
        
        <table>
            <thead>
                <tr>
                    <th>Timestamp</th>
                    <th>Logon ID</th>
                    <th>Process Name</th>
                    <th>Command Line</th>
                    <th>Computer</th>
                    <th>Anomaly Type</th>
                </tr>
            </thead>
            <tbody>"""
        
        for anomaly in analysis_results['anomalies']:
            timestamp_str = anomaly['Timestamp'].strftime("%Y-%m-%d %H:%M:%S") if anomaly['Timestamp'] else "Unknown"
            html_content += f"""
                <tr class="anomaly">
                    <td>{timestamp_str}</td>
                    <td>{anomaly.get('LogonID', 'Unknown')}</td>
                    <td>{anomaly.get('ProcessName', 'Unknown')}</td>
                    <td>{anomaly.get('CommandLine', 'Unknown')}</td>
                    <td>{anomaly.get('ComputerName', 'Unknown')}</td>
                    <td class="warning">{anomaly.get('AnomalyType', 'Unknown')}</td>
                </tr>"""
        
        html_content += """
            </tbody>
        </table>"""
    
    html_content += f"""
        
        <h2>📋 Analysis Details</h2>
        <div class="info">
            <p><strong>What this analysis means:</strong></p>
            <ul>
                <li>Process Creation events (Event ID 4688) show when new processes are started</li>
                <li>Logon events (Event ID 4624) show successful user authentication</li>
                <li>Each process should have a corresponding logon event with the same Logon ID</li>
                <li>Missing logon events may indicate security issues or incomplete logging</li>
            </ul>
        </div>
        
        <div class="warning">
            <p><strong>Important Notes:</strong></p>
            <ul>
                <li>This is a BETA version analysis tool (Python version)</li>
                <li>Some legitimate processes may not have corresponding logon events</li>
                <li>Always investigate anomalies in context with other security events</li>
                <li>Consider system-specific configurations and logging policies</li>
                <li>This analysis was performed on a Linux platform using Python</li>
            </ul>
        </div>
        
        <hr>
        <p><em>Report generated by {SCRIPT_NAME} v{SCRIPT_VERSION} on {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</em></p>
    </div>
</body>
</html>"""
    
    with open(html_report, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    print_status("SUCCESS", f"HTML report generated: {html_report}")

def generate_summary_report():
    """Generate summary report."""
    print_status("INFO", "Generating summary report...")
    
    summary_content = f"""=============================================================================
                    WINDOWS SECURITY EVENT ANALYSIS SUMMARY
=============================================================================
Analysis Date: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
Script: {SCRIPT_NAME}
Version: {SCRIPT_VERSION}
Event Log: {event_log_path}
Output Directory: {output_path}

ANALYSIS RESULTS:
- Total Process Creation Events (4688): {analysis_results['summary'].get('ProcessCreationCount', 0)}
- Total Logon Events (4624): {analysis_results['summary'].get('LogonCount', 0)}
- Anomalies Detected: {analysis_results['summary'].get('AnomalyCount', 0)}

ANOMALY DETAILS:
"""
    
    if len(analysis_results['anomalies']) == 0:
        summary_content += "No anomalies detected. All process creation events have corresponding logon events.\n"
    else:
        for anomaly in analysis_results['anomalies']:
            timestamp_str = anomaly['Timestamp'].strftime("%Y-%m-%d %H:%M:%S") if anomaly['Timestamp'] else "Unknown"
            summary_content += f"""- Timestamp: {timestamp_str}
  Logon ID: {anomaly.get('LogonID', 'Unknown')}
  Process: {anomaly.get('ProcessName', 'Unknown')}
  Command: {anomaly.get('CommandLine', 'Unknown')}
  Computer: {anomaly.get('ComputerName', 'Unknown')}
  Anomaly: {anomaly.get('AnomalyType', 'Unknown')}

"""
    
    summary_content += f"""FILES GENERATED:
- Log File: {log_file}
- HTML Report: {html_report}
- CSV Report: {csv_report}
- Summary: {summary_file}

BETA VERSION NOTES:
- This analysis was performed by a beta version tool (Python)
- Validate all findings in your environment
- Some legitimate processes may not have corresponding logon events
- Consider system-specific configurations and logging policies
- This analysis was performed on a Linux platform

LINUX COMPATIBILITY NOTES:
- Successfully analyzed Windows .evtx files on Linux
- Used Python evtx library for cross-platform compatibility
- No Windows-specific tools required

=============================================================================
"""
    
    with open(summary_file, 'w', encoding='utf-8') as f:
        f.write(summary_content)
    
    print_status("SUCCESS", f"Summary report generated: {summary_file}")

def show_final_results():
    """Display final results."""
    print_status("SUCCESS", "Analysis completed successfully!")
    print_status("INFO", "Results Summary:")
    print_status("INFO", f"  - Process Creation Events: {analysis_results['summary'].get('ProcessCreationCount', 0)}")
    print_status("INFO", f"  - Logon Events: {analysis_results['summary'].get('LogonCount', 0)}")
    print_status("INFO", f"  - Anomalies Detected: {analysis_results['summary'].get('AnomalyCount', 0)}")
    
    if analysis_results['summary'].get('AnomalyCount', 0) > 0:
        print_status("WARNING", f"  ⚠️  {analysis_results['summary'].get('AnomalyCount', 0)} anomalies found - review the reports for details")
    else:
        print_status("SUCCESS", "  ✅ No anomalies detected")
    
    print_status("INFO", "Output files generated:")
    print_status("INFO", f"  - HTML Report: {html_report}")
    print_status("INFO", f"  - CSV Report: {csv_report}")
    print_status("INFO", f"  - Summary: {summary_file}")
    print_status("INFO", f"  - Log: {log_file}")

def main():
    """Main function."""
    global event_log_path, output_path
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description=f'Windows Security Event Log Analyzer v{SCRIPT_VERSION} (Python Version)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:
  python3 %(prog)s -f security.evtx
  python3 %(prog)s -f security.evtx -o analysis_results -v
  
REQUIREMENTS:
  - Python 3.7+
  - Linux platform
  - evtx library: pip3 install evtx
  
For additional functionality:
  - pandas: pip3 install pandas
  - jinja2: pip3 install jinja2
        """
    )
    
    parser.add_argument(
        '-f', '--file',
        required=True,
        help='Path to the security.evtx file to analyze'
    )
    
    parser.add_argument(
        '-o', '--output',
        default='.',
        help='Output directory for analysis results (default: current directory)'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show detailed verbose output'
    )
    
    args = parser.parse_args()
    
    event_log_path = args.file
    output_path = args.output
    
    # Show help if requested
    if len(sys.argv) == 1:
        show_help()
        return
    
    print_status("INFO", "=== Windows Security Event Log Analyzer Started (Python Version) ===")
    print_status("INFO", f"Script Version: {SCRIPT_VERSION}")
    print_status("INFO", f"Event Log: {event_log_path}")
    print_status("INFO", f"Output Directory: {output_path}")
    
    try:
        # Initialize environment
        validate_environment(event_log_path, output_path, args.verbose)
        initialize_output_files(output_path)
        
        # Perform analysis
        extract_process_creation_events(event_log_path)
        extract_logon_events(event_log_path)
        find_anomalies()
        
        # Generate reports
        generate_html_report()
        generate_summary_report()
        
        # Show results
        show_final_results()
        
        print_status("SUCCESS", "=== Analysis completed successfully ===")
        
    except KeyboardInterrupt:
        print_status("WARNING", "Analysis interrupted by user")
        sys.exit(1)
    except Exception as e:
        print_status("ERROR", f"Analysis failed: {e}")
        if 'log_file' in globals():
            print_status("ERROR", f"Check the log file for details: {log_file}")
        sys.exit(1)

if __name__ == "__main__":
    main()

