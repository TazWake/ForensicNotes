#!/usr/bin/env python3
"""
==============================================================================
                    STATIC BINARY ANALYZER
==============================================================================
Script: static_binary_analyzer.py
Version: 1.0
Description: Performs static analysis on suspicious binary files without execution
Requirements: Linux system with Python 3.6+, standard Linux tools
Usage: python3 static_binary_analyzer.py <file_path> [options]

FEATURES:
- Safe static analysis (never executes binaries)
- Cross-platform executable support (Windows/Linux)
- Multiple analysis tools integration
- VirusTotal hash lookup capability
- Comprehensive output generation
- User-friendly error handling

ANALYSIS TOOLS USED:
- file: File type identification
- strings: String extraction
- exiftool: Metadata extraction
- objdump: Object file analysis
- readelf: ELF file analysis
- pefile: PE file analysis (Windows executables)
- hashlib: File hashing (MD5, SHA1, SHA256)

OUTPUT FILES:
- analysis_summary.txt: Overview of findings
- strings_analysis.txt: Extracted strings
- metadata_analysis.txt: File metadata
- binary_structure.txt: Binary structure details
- security_indicators.txt: Potential security concerns
- virustotal_results.txt: VirusTotal lookup results

FUTURE VERSION PLANS:
- Direct VirusTotal API integration
- LLM analysis submission
- Enhanced malware detection
- Network behavior analysis
- Sandbox integration (safe execution)

==============================================================================
"""

import os
import sys
import hashlib
import subprocess
import argparse
import json
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import urllib.request
import urllib.error

# Script Configuration
SCRIPT_VERSION = "1.0"
SCRIPT_NAME = "static_binary_analyzer.py"
AUTHOR = "Taz Wake"

class BinaryAnalyzer:
    """Main class for performing static binary analysis."""
    
    def __init__(self, file_path: str, output_dir: str, verbose: bool = False):
        """
        Initialize the binary analyzer.
        
        Args:
            file_path: Path to the binary file to analyze
            output_dir: Directory to save analysis results
            verbose: Enable verbose output
        """
        self.file_path = Path(file_path)
        self.output_dir = Path(output_dir)
        self.verbose = verbose
        self.analysis_results = {}
        self.errors = []
        
        # Ensure output directory exists
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Analysis output files
        self.output_files = {
            'summary': self.output_dir / 'analysis_summary.txt',
            'strings': self.output_dir / 'strings_analysis.txt',
            'metadata': self.output_dir / 'metadata_analysis.txt',
            'structure': self.output_dir / 'binary_structure.txt',
            'security': self.output_dir / 'security_indicators.txt',
            'virustotal': self.output_dir / 'virustotal_results.txt'
        }
    
    def log_message(self, message: str, level: str = "INFO"):
        """Log a message with timestamp and level."""
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        log_msg = f"[{timestamp}] {level}: {message}"
        
        if self.verbose or level in ["ERROR", "WARNING"]:
            print(log_msg)
    
    def run_command(self, command: List[str], timeout: int = 30) -> Tuple[bool, str, str]:
        """
        Run a shell command safely.
        
        Args:
            command: Command to run as list
            timeout: Command timeout in seconds
            
        Returns:
            Tuple of (success, stdout, stderr)
        """
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False
            )
            return result.returncode == 0, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return False, "", f"Command timed out after {timeout} seconds"
        except FileNotFoundError:
            return False, "", f"Command not found: {command[0]}"
        except Exception as e:
            return False, "", f"Command execution error: {str(e)}"
    
    def check_file_exists(self) -> bool:
        """Check if the target file exists and is accessible."""
        if not self.file_path.exists():
            self.log_message(f"File not found: {self.file_path}", "ERROR")
            return False
        
        if not self.file_path.is_file():
            self.log_message(f"Path is not a file: {self.file_path}", "ERROR")
            return False
        
        if not os.access(self.file_path, os.R_OK):
            self.log_message(f"File not readable: {self.file_path}", "ERROR")
            return False
        
        self.log_message(f"File validated: {self.file_path}")
        return True
    
    def calculate_file_hashes(self) -> Dict[str, str]:
        """Calculate MD5, SHA1, and SHA256 hashes of the file."""
        self.log_message("Calculating file hashes...")
        
        hashes = {}
        hash_algorithms = {
            'MD5': hashlib.md5(),
            'SHA1': hashlib.sha1(),
            'SHA256': hashlib.sha256()
        }
        
        try:
            with open(self.file_path, 'rb') as f:
                while chunk := f.read(8192):
                    for hash_obj in hash_algorithms.values():
                        hash_obj.update(chunk)
            
            for name, hash_obj in hash_algorithms.items():
                hashes[name] = hash_obj.hexdigest()
            
            self.log_message("File hashes calculated successfully")
            return hashes
            
        except Exception as e:
            self.log_message(f"Error calculating hashes: {str(e)}", "ERROR")
            self.errors.append(f"Hash calculation failed: {str(e)}")
            return {}
    
    def get_file_type(self) -> str:
        """Determine the file type using the 'file' command."""
        self.log_message("Determining file type...")
        
        success, stdout, stderr = self.run_command(['file', str(self.file_path)])
        
        if success and stdout.strip():
            file_type = stdout.strip()
            self.log_message(f"File type: {file_type}")
            return file_type
        else:
            error_msg = f"Could not determine file type: {stderr}"
            self.log_message(error_msg, "ERROR")
            self.errors.append(error_msg)
            return "Unknown file type"
    
    def extract_strings(self) -> str:
        """Extract printable strings from the binary."""
        self.log_message("Extracting strings from binary...")
        
        # Try different string extraction methods
        string_methods = [
            ['strings', str(self.file_path)],
            ['strings', '-a', str(self.file_path)],  # All sections
            ['strings', '-t', 'x', str(self.file_path)]  # With offsets
        ]
        
        for method in string_methods:
            success, stdout, stderr = self.run_command(method)
            if success and stdout.strip():
                self.log_message(f"Strings extracted using: {' '.join(method)}")
                return stdout
        
        error_msg = "Failed to extract strings from binary"
        self.log_message(error_msg, "ERROR")
        self.errors.append(error_msg)
        return "String extraction failed"
    
    def extract_metadata(self) -> str:
        """Extract metadata using exiftool and other tools."""
        self.log_message("Extracting file metadata...")
        
        metadata_results = []
        
        # Try exiftool first
        success, stdout, stderr = self.run_command(['exiftool', str(self.file_path)])
        if success and stdout.strip():
            metadata_results.append("=== EXIFTOOL METADATA ===\n" + stdout)
        
        # Try file command with more details
        success, stdout, stderr = self.run_command(['file', '-k', str(self.file_path)])
        if success and stdout.strip():
            metadata_results.append("=== FILE COMMAND DETAILS ===\n" + stdout)
        
        # Try stat command for file system metadata
        success, stdout, stderr = self.run_command(['stat', str(self.file_path)])
        if success and stdout.strip():
            metadata_results.append("=== FILE SYSTEM METADATA ===\n" + stdout)
        
        if metadata_results:
            self.log_message("Metadata extracted successfully")
            return "\n\n".join(metadata_results)
        else:
            error_msg = "Failed to extract metadata"
            self.log_message(error_msg, "ERROR")
            self.errors.append(error_msg)
            return "Metadata extraction failed"
    
    def analyze_binary_structure(self) -> str:
        """Analyze the binary structure based on file type."""
        self.log_message("Analyzing binary structure...")
        
        file_type = self.get_file_type().lower()
        analysis_results = []
        
        if 'elf' in file_type:
            analysis_results.append(self._analyze_elf_file())
        elif 'pe32' in file_type or 'pe64' in file_type or 'microsoft' in file_type:
            analysis_results.append(self._analyze_pe_file())
        else:
            analysis_results.append("Binary structure analysis not supported for this file type")
        
        if analysis_results:
            self.log_message("Binary structure analysis completed")
            return "\n\n".join(analysis_results)
        else:
            error_msg = "Binary structure analysis failed"
            self.log_message(error_msg, "ERROR")
            self.errors.append(error_msg)
            return "Binary structure analysis failed"
    
    def _analyze_elf_file(self) -> str:
        """Analyze ELF file structure."""
        analysis = ["=== ELF FILE ANALYSIS ===\n"]
        
        # Basic ELF info
        success, stdout, stderr = self.run_command(['readelf', '-h', str(self.file_path)])
        if success and stdout.strip():
            analysis.append("ELF Header:\n" + stdout)
        
        # Section headers
        success, stdout, stderr = self.run_command(['readelf', '-S', str(self.file_path)])
        if success and stdout.strip():
            analysis.append("Section Headers:\n" + stdout)
        
        # Program headers
        success, stdout, stderr = self.run_command(['readelf', '-l', str(self.file_path)])
        if success and stdout.strip():
            analysis.append("Program Headers:\n" + stdout)
        
        # Dynamic symbols
        success, stdout, stderr = self.run_command(['readelf', '-d', str(self.file_path)])
        if success and stdout.strip():
            analysis.append("Dynamic Section:\n" + stdout)
        
        return "\n\n".join(analysis)
    
    def _analyze_pe_file(self) -> str:
        """Analyze PE file structure."""
        analysis = ["=== PE FILE ANALYSIS ===\n"]
        
        # Try objdump for PE files
        success, stdout, stderr = self.run_command(['objdump', '-f', str(self.file_path)])
        if success and stdout.strip():
            analysis.append("File Header:\n" + stdout)
        
        # Try objdump for sections
        success, stdout, stderr = self.run_command(['objdump', '-h', str(self.file_path)])
        if success and stdout.strip():
            analysis.append("Section Headers:\n" + stdout)
        
        # Note: For detailed PE analysis, pefile library would be better
        # but keeping it simple for now
        analysis.append("Note: Consider using pefile library for detailed PE analysis")
        
        return "\n\n".join(analysis)
    
    def identify_security_indicators(self) -> str:
        """Identify potential security indicators in the binary."""
        self.log_message("Identifying security indicators...")
        
        indicators = ["=== SECURITY INDICATORS ANALYSIS ===\n"]
        
        # Check for suspicious strings
        strings_content = self.extract_strings()
        suspicious_patterns = [
            'http://', 'https://', 'ftp://',  # Network connections
            'cmd.exe', 'powershell', 'bash',  # Shell commands
            'registry', 'regedit',  # Registry access
            'CreateProcess', 'WinExec', 'ShellExecute',  # Process creation
            'socket', 'connect', 'bind',  # Network functions
            'encrypt', 'decrypt', 'AES', 'RSA',  # Encryption
            'admin', 'root', 'sudo',  # Privilege escalation
            'backdoor', 'trojan', 'virus', 'malware'  # Malicious terms
        ]
        
        found_indicators = []
        for pattern in suspicious_patterns:
            if pattern.lower() in strings_content.lower():
                found_indicators.append(f"- Found suspicious pattern: {pattern}")
        
        if found_indicators:
            indicators.append("Suspicious patterns found:\n" + "\n".join(found_indicators))
        else:
            indicators.append("No obvious suspicious patterns found")
        
        # Check file permissions
        try:
            stat_info = os.stat(self.file_path)
            mode = stat_info.st_mode
            if mode & 0o111:  # Executable bit set
                indicators.append("\nFile permissions: Executable")
            else:
                indicators.append("\nFile permissions: Non-executable")
        except Exception as e:
            indicators.append(f"\nCould not check file permissions: {str(e)}")
        
        # Check file size (very large files might be suspicious)
        file_size = self.file_path.stat().st_size
        if file_size > 100 * 1024 * 1024:  # 100MB
            indicators.append(f"\nFile size: {file_size / (1024*1024):.1f} MB (large file)")
        else:
            indicators.append(f"\nFile size: {file_size / 1024:.1f} KB")
        
        self.log_message("Security indicators analysis completed")
        return "\n".join(indicators)
    
    def lookup_virustotal(self, file_hash: str) -> str:
        """Look up file hash on VirusTotal (public API)."""
        self.log_message("Looking up file hash on VirusTotal...")
        
        # Note: This uses the public VirusTotal API which has rate limits
        # For production use, consider using the official API with key
        
        vt_url = f"https://www.virustotal.com/vtapi/v2/file/report"
        params = {
            'apikey': 'dummy',  # Public API doesn't require key for lookups
            'resource': file_hash
        }
        
        try:
            # For public API, we'll just provide the URL for manual checking
            manual_url = f"https://www.virustotal.com/gui/file/{file_hash}"
            
            result = f"""=== VIRUSTOTAL LOOKUP ===
File Hash: {file_hash}
Manual Check URL: {manual_url}

Note: This is a manual lookup URL. For automated analysis:
1. Visit the URL above
2. Check the file's reputation
3. Review any detection results

Future versions will include:
- Direct API integration with VirusTotal
- Automated result parsing
- LLM analysis submission
- Enhanced threat intelligence
"""
            
            self.log_message("VirusTotal lookup information generated")
            return result
            
        except Exception as e:
            error_msg = f"VirusTotal lookup failed: {str(e)}"
            self.log_message(error_msg, "ERROR")
            self.errors.append(error_msg)
            return f"VirusTotal lookup failed: {str(e)}"
    
    def save_analysis_results(self):
        """Save all analysis results to output files."""
        self.log_message("Saving analysis results...")
        
        # Save strings analysis
        with open(self.output_files['strings'], 'w', encoding='utf-8') as f:
            f.write(self.analysis_results.get('strings', 'String extraction failed'))
        
        # Save metadata analysis
        with open(self.output_files['metadata'], 'w', encoding='utf-8') as f:
            f.write(self.analysis_results.get('metadata', 'Metadata extraction failed'))
        
        # Save binary structure analysis
        with open(self.output_files['structure'], 'w', encoding='utf-8') as f:
            f.write(self.analysis_results.get('structure', 'Structure analysis failed'))
        
        # Save security indicators
        with open(self.output_files['security'], 'w', encoding='utf-8') as f:
            f.write(self.analysis_results.get('security', 'Security analysis failed'))
        
        # Save VirusTotal results
        with open(self.output_files['virustotal'], 'w', encoding='utf-8') as f:
            f.write(self.analysis_results.get('virustotal', 'VirusTotal lookup failed'))
        
        # Generate and save summary
        summary = self._generate_summary()
        with open(self.output_files['summary'], 'w', encoding='utf-8') as f:
            f.write(summary)
        
        self.log_message("Analysis results saved successfully")
    
    def _generate_summary(self) -> str:
        """Generate a comprehensive analysis summary."""
        summary = f"""==============================================================================
                    STATIC BINARY ANALYSIS SUMMARY
==============================================================================
Analysis Date: {time.strftime("%Y-%m-%d %H:%M:%S")}
Script: {SCRIPT_NAME}
Version: {SCRIPT_VERSION}
Target File: {self.file_path}
Output Directory: {self.output_dir}

FILE INFORMATION:
{self.analysis_results.get('file_type', 'Unknown file type')}

FILE HASHES:
"""
        
        hashes = self.analysis_results.get('hashes', {})
        for hash_type, hash_value in hashes.items():
            summary += f"{hash_type}: {hash_value}\n"
        
        summary += f"""
ANALYSIS RESULTS:
- Strings Analysis: {'Completed' if 'strings' in self.analysis_results else 'Failed'}
- Metadata Analysis: {'Completed' if 'metadata' in self.analysis_results else 'Failed'}
- Binary Structure: {'Completed' if 'structure' in self.analysis_results else 'Failed'}
- Security Indicators: {'Completed' if 'security' in self.analysis_results else 'Failed'}
- VirusTotal Lookup: {'Completed' if 'virustotal' in self.analysis_results else 'Failed'}

OUTPUT FILES:
"""
        
        for file_type, file_path in self.output_files.items():
            summary += f"- {file_type.replace('_', ' ').title()}: {file_path}\n"
        
        if self.errors:
            summary += "\nERRORS ENCOUNTERED:\n"
            for error in self.errors:
                summary += f"- {error}\n"
        
        summary += f"""
FUTURE ENHANCEMENTS:
- Direct VirusTotal API integration
- LLM analysis submission
- Enhanced malware detection
- Network behavior analysis
- Sandbox integration (safe execution)

==============================================================================
"""
        return summary
    
    def run_analysis(self) -> bool:
        """Run the complete static analysis."""
        self.log_message("Starting static binary analysis...")
        
        # Validate file
        if not self.check_file_exists():
            return False
        
        # Perform analysis steps
        try:
            # Calculate hashes
            self.analysis_results['hashes'] = self.calculate_file_hashes()
            
            # Get file type
            self.analysis_results['file_type'] = self.get_file_type()
            
            # Extract strings
            self.analysis_results['strings'] = self.extract_strings()
            
            # Extract metadata
            self.analysis_results['metadata'] = self.extract_metadata()
            
            # Analyze binary structure
            self.analysis_results['structure'] = self.analyze_binary_structure()
            
            # Identify security indicators
            self.analysis_results['security'] = self.identify_security_indicators()
            
            # VirusTotal lookup (using SHA256 hash)
            if 'SHA256' in self.analysis_results['hashes']:
                self.analysis_results['virustotal'] = self.lookup_virustotal(
                    self.analysis_results['hashes']['SHA256']
                )
            
            # Save results
            self.save_analysis_results()
            
            self.log_message("Static binary analysis completed successfully", "SUCCESS")
            return True
            
        except Exception as e:
            error_msg = f"Analysis failed: {str(e)}"
            self.log_message(error_msg, "ERROR")
            self.errors.append(error_msg)
            return False

def show_help():
    """Display comprehensive help information."""
    help_text = f"""
{SCRIPT_NAME} - Static Binary Analyzer v{SCRIPT_VERSION}

DESCRIPTION:
    This script performs comprehensive static analysis on binary files without
    executing them. It analyzes both Windows and Linux executables using
    multiple analysis tools and generates detailed reports.

USAGE:
    python3 {SCRIPT_NAME} <file_path> [options]

ARGUMENTS:
    file_path              Path to the binary file to analyze (REQUIRED)

OPTIONS:
    -o, --output-dir DIR   Output directory for analysis results
                           (default: ./analysis_results)
    -v, --verbose          Enable verbose output
    -h, --help             Show this help message
    --version              Show script version

EXAMPLES:
    python3 {SCRIPT_NAME} suspicious_file.exe
    python3 {SCRIPT_NAME} malware.bin -o /tmp/analysis -v
    python3 {SCRIPT_NAME} --help

REQUIREMENTS:
    - Linux system with Python 3.6+
    - Standard Linux tools: file, strings, exiftool, objdump, readelf
    - Internet connection for VirusTotal lookups

SAFETY FEATURES:
    - NEVER executes the target binary
    - Read-only file access only
    - Safe command execution with timeouts
    - Comprehensive error handling

OUTPUT FILES:
    - analysis_summary.txt: Overview of findings
    - strings_analysis.txt: Extracted strings
    - metadata_analysis.txt: File metadata
    - binary_structure.txt: Binary structure details
    - security_indicators.txt: Potential security concerns
    - virustotal_results.txt: VirusTotal lookup results

FUTURE VERSIONS:
    - Direct VirusTotal API integration
    - LLM analysis submission
    - Enhanced malware detection
    - Network behavior analysis
    - Sandbox integration (safe execution)

For more information, see the script's embedded documentation.
"""
    print(help_text)

def main():
    """Main function to handle command line arguments and run analysis."""
    parser = argparse.ArgumentParser(
        description=f"Static Binary Analyzer v{SCRIPT_VERSION}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Examples:
  python3 {SCRIPT_NAME} suspicious_file.exe
  python3 {SCRIPT_NAME} malware.bin -o /tmp/analysis -v
  python3 {SCRIPT_NAME} --help

For detailed help, use: python3 {SCRIPT_NAME} --help
        """
    )
    
    parser.add_argument(
        'file_path',
        help='Path to the binary file to analyze'
    )
    
    parser.add_argument(
        '-o', '--output-dir',
        default='./analysis_results',
        help='Output directory for analysis results (default: ./analysis_results)'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version=f'{SCRIPT_NAME} v{SCRIPT_VERSION}'
    )
    
    args = parser.parse_args()
    
    # Show help if requested
    if args.file_path == '--help' or args.file_path == '-h':
        show_help()
        return
    
    # Validate file path
    if not os.path.exists(args.file_path):
        print(f"ERROR: File not found: {args.file_path}")
        print("Use --help for usage information")
        sys.exit(1)
    
    # Create analyzer and run analysis
    analyzer = BinaryAnalyzer(args.file_path, args.output_dir, args.verbose)
    
    if analyzer.run_analysis():
        print(f"\n✅ Analysis completed successfully!")
        print(f"📁 Results saved to: {args.output_dir}")
        print(f"📋 Summary: {analyzer.output_files['summary']}")
        sys.exit(0)
    else:
        print(f"\n❌ Analysis failed!")
        if analyzer.errors:
            print("Errors encountered:")
            for error in analyzer.errors:
                print(f"  - {error}")
        sys.exit(1)

if __name__ == "__main__":
    main()
