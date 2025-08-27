# AskJOE 2.0 - Advanced Malware Analysis Suite

[![GitHub stars](https://img.shields.io/github/stars/securityjoes/AskJOE)](https://github.com/securityjoes/AskJOE/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/securityjoes/AskJOE)](https://github.com/securityjoes/AskJOE/network)
[![GitHub issues](https://img.shields.io/github/issues/securityjoes/securityjoes/AskJOE)](https://github.com/securityjoes/AskJOE/issues)
[![License](https://img.shields.io/badge/License-GPL_v2-blue.svg)](LICENSE)

> **AI-Powered Malware Analysis & Threat Intelligence for Ghidra**  
> Transform your static analysis workflow with cutting-edge AI capabilities, comprehensive malware detection, and advanced threat intelligence.
## 🚀 What is AskJOE 2.0?

AskJOE 2.0 is an evolution of the original [AskJOE project](https://github.com/securityjoes/AskJOE), transforming it from a single AI-powered function analyzer into a comprehensive malware analysis suite. Built on the foundation of Ghidra and OpenAI integration, this enhanced version adds 8 specialized analysis modules that provide deep insights into malware behavior, threat intelligence, and reverse engineering analysis.

### ✨ Evolution from AskJOE 1.0

**Original AskJOE Features:**
- AI-powered function analysis using OpenAI
- Basic reverse engineering assistance
- Function explanation and simplification
- Stack string recovery
- Crypto constant detection

**AskJOE 2.0 Enhancements:**
- **8 Specialized Analysis Scripts** for comprehensive malware analysis
- **Multi-source Threat Intelligence** integration (9 OSINT services)
- **Advanced Behavioral Analysis** with sandbox integration
- **Enhanced CAPA Analysis** with symbol creation
- **Comprehensive Logging & Monitoring** system
- **Configurable Analysis Pipeline** with rate limiting
- **Professional-grade Output** with detailed threat assessments

## 🛠️ Core Analysis Modules

### 1. **AI Triage Analysis** (`01_AI_Triage_Analysis.py`)
- **Purpose**: Initial malware assessment using AI analysis
- **Features**: 
  - Automated threat classification
  - Behavioral pattern recognition
  - Risk assessment and prioritization
  - AI-powered analysis recommendations

### 2. **CAPA Analysis** (`02_CAPA_Analysis.py`)
- **Purpose**: Advanced malware capability analysis using Mandiant CAPA
- **Features**:
  - Malware behavior detection
  - Attack technique identification
  - Symbol table integration in Ghidra
  - Comprehensive rule matching
  - Enhanced output formatting

### 3. **Function Analyzer** (`03_Function_Analyzer.py`)
- **Purpose**: Deep function-level analysis and documentation
- **Features**:
  - Function behavior analysis
  - Cross-reference mapping
  - Call graph analysis
  - Documentation generation

### 4. **Function Simplifier** (`04_Function_Simplifier.py`)
- **Purpose**: Code complexity reduction and readability enhancement
- **Features**:
  - Decompiled code simplification
  - Variable renaming optimization
  - Control flow clarification
  - Readability improvements

### 5. **Crypto Detector** (`05_Crypto_Detector.py`)
- **Purpose**: Cryptographic algorithm and constant identification
- **Features**:
  - Encryption algorithm detection
  - Hash function identification
  - Cryptographic constant analysis
  - Integration with AskJOE data sources

### 6. **Stack Strings Detector** (`06_Stack_Strings_Detector.py`)
- **Purpose**: Advanced string recovery and analysis
- **Features**:
  - Dynamic string reconstruction
  - Entropy-based filtering
  - Validation algorithms
  - Configurable detection parameters

### 7. **XOR Searcher** (`07_XOR_Searcher.py`)
- **Purpose**: XOR obfuscation detection and decoding
- **Features**:
  - XOR operation identification
  - Brute-force decoding (0x01-0xFF)
  - Self-XOR filtering
  - Clickable address output
  - Suspicious operation highlighting

### 8. **Threat Intelligence Analyzer** (`08_Threat_Intelligence_Analyzer.py`)
- **Purpose**: Comprehensive threat intelligence gathering and analysis
- **Features**:
  - **9 OSINT Service Integration**:
    - VirusTotal (comprehensive malware analysis)
    - Hybrid Analysis (sandbox behavioral analysis)
    - AlienVault OTX (threat intelligence)
    - Malware Bazaar (malware family identification)
    - Intezer (genetic malware analysis)
    - Any.Run (advanced sandbox analysis)
    - Triage (malware analysis platform)
    - X-Force Exchange (IBM threat intelligence)
  - **Real-time Status Monitoring** for all services
  - **Comprehensive Threat Assessment** with malware family detection
  - **Rate Limiting & Error Handling** for robust API integration
  - **Detailed Logging & Debugging** capabilities

## 🔧 Technical Features

### **Enhanced Configuration System**
- **Centralized Configuration** (`config.ini`)
- **API Key Management** for all intelligence services
- **Rate Limiting Controls** to prevent API abuse
- **Feature Toggles** for enabling/disabling specific services
- **Logging Configuration** with customizable formats

### **Advanced Logging & Monitoring**
- **Structured Logging** with multiple log levels
- **Service Status Tracking** for all intelligence sources
- **Performance Monitoring** and error reporting
- **Debug Information** for troubleshooting
- **Comprehensive Audit Trail**

### **Robust Error Handling**
- **Graceful Degradation** when services fail
- **Retry Mechanisms** for transient failures
- **Fallback Strategies** for critical analysis
- **User-friendly Error Messages**
- **Detailed Debug Information**

### **Professional Output Formatting**
- **Structured Analysis Reports**
- **Threat Level Classifications** (CRITICAL, HIGH, MEDIUM, LOW)
- **Comprehensive Threat Assessments**
- **Hunting Guidance** with direct links to intelligence sources
- **Clickable Addresses** for Ghidra navigation

## 🚀 Installation & Setup

### **Prerequisites**
```bash
# Core dependencies
pip install requests openai flare-capa

# Ghidra with Ghidrathon support
# Python 3.7+ with PyGhidra
```

### **Installation Steps**
1. **Clone/Download** the AskJOE 2.0 scripts
2. **Place Scripts** in your `ghidra_scripts` directory
3. **Configure API Keys** in `AskJOE/config.ini`
4. **Enable Features** as needed in configuration
5. **Run Scripts** from Ghidra's Script Manager

### **Configuration Example**
```ini
[API_KEYS]
virustotal_api_key = YOUR_VT_API_KEY
hybrid_analysis_api_key = YOUR_HA_API_KEY
alienvault_api_key = YOUR_OTX_API_KEY
malware_bazaar_api_key = YOUR_MB_API_KEY
intezer_api_key = YOUR_INTEZER_API_KEY
anyrun_api_key = YOUR_ANYRUN_API_KEY
triage_api_key = YOUR_TRIAGE_API_KEY
xforce_api_key = YOUR_XFORCE_API_KEY

[FEATURES]
enable_virustotal = true
enable_hybrid_analysis = true
enable_alienvault = true
enable_malware_bazaar = true
enable_intezer = true
enable_anyrun = true
enable_triage = true
enable_xforce = true
```

## 📊 Usage Examples

### **Comprehensive Malware Analysis Workflow**
```python
# 1. Start with AI Triage for initial assessment
# 2. Run CAPA Analysis for capability detection
# 3. Use Function Analyzer for deep code analysis
# 4. Apply Crypto Detector for encryption analysis
# 5. Run Stack Strings Detector for string recovery
# 6. Execute XOR Searcher for obfuscation detection
# 7. Complete with Threat Intelligence Analyzer
```

### **Threat Intelligence Analysis Output**
```
================================================================================
COMPREHENSIVE THREAT INTELLIGENCE ANALYSIS RESULTS
================================================================================
Threat Level: CRITICAL
Detection Rate: 54/Unknown
Detection Percentage: 100.0%
File Hash: 5bde316bb02a4d1c0e5530093c04f48e6bb862a828f154b5ad2a19c3a032937d
Sources Queried: 3/8

[SERVICE STATUS SUMMARY]
  [SUCCESS] VirusTotal: 54 detections
  [SUCCESS] Hybrid Analysis: verdict: malicious
  [SUCCESS] AlienVault: 0 pulses
  [FAILED] Malware Bazaar: API error: 404
  Summary: 3/8 services successful

=== COMPREHENSIVE THREAT ASSESSMENT ===
  [SANDBOX VERDICTS] malicious
  [THREAT TAGS] assembly, calls-wmi, checks-cpu-name, detect-debug-environment
  File Type: Win32 EXE
  File Size: 250504 bytes
```

## 🔍 Key Capabilities

### **Malware Family Detection**
- **Multi-source Family Identification** from 9 intelligence services
- **Behavioral Pattern Recognition** using sandbox analysis
- **Threat Tag Aggregation** across all sources
- **Comprehensive Family Mapping** with confidence scoring

### **Advanced Behavioral Analysis**
- **Sandbox Integration** with Hybrid Analysis and Any.Run
- **Process Behavior Monitoring** and analysis
- **Network Activity Tracking** and C2 detection
- **File System Changes** and persistence analysis

### **Intelligence Correlation**
- **Cross-source Data Validation** for accuracy
- **Threat Level Calculation** based on multiple factors
- **Risk Assessment** with actionable recommendations
- **Hunting Guidance** with direct intelligence links

## 🎯 Use Cases

### **Incident Response**
- **Rapid Malware Assessment** and classification
- **Threat Intelligence Gathering** for containment
- **Behavioral Analysis** for eradication planning
- **Comprehensive Reporting** for stakeholders

### **Malware Research**
- **Deep Code Analysis** and reverse engineering
- **Family Classification** and attribution
- **Behavioral Pattern** identification
- **Threat Landscape** analysis

### **Security Operations**
- **Automated Analysis** workflows
- **Threat Hunting** and investigation
- **Intelligence Sharing** and collaboration
- **Risk Assessment** and prioritization

## 🔧 Advanced Configuration

### **Rate Limiting & Performance**
```ini
[CONFIGURATION]
api_timeout = 30
api_rate_limit_delay = 1
max_retries = 3
```

### **Analysis Parameters**
```ini
[STACK_STRINGS]
min_string_length = 4
max_string_length = 100
min_entropy = 3.0
validation_ratio = 0.7
```

### **Logging Configuration**
```ini
[LOGGING]
log_level = INFO
log_format = %%(asctime)s - %%(name)s - %%(levelname)s - %%(message)s
log_file = AskJOE_analysis.log
```

## 🚨 Troubleshooting

### **Common Issues & Solutions**

**API Key Errors:**
- Verify all API keys in `config.ini`
- Check API key permissions and quotas
- Ensure proper endpoint URLs

**Service Failures:**
- Review service status in output
- Check network connectivity
- Verify API service availability

**Performance Issues:**
- Adjust rate limiting parameters
- Monitor API quotas
- Check system resources

## 🤝 Contributing

### **Development Guidelines**
- **Maintain Compatibility** with Ghidra and PyGhidra
- **Follow Error Handling** patterns established
- **Add Comprehensive Logging** for new features
- **Update Configuration** options as needed

### **Feature Requests**
- **Enhance Intelligence Sources** with new OSINT services
- **Improve Analysis Algorithms** for better detection
- **Add Export Formats** for integration with other tools
- **Enhance UI/UX** for better user experience

## 📈 Roadmap

### **Planned Enhancements**
- **Machine Learning Integration** for improved detection
- **Additional Sandbox Services** for broader coverage
- **Real-time Intelligence Feeds** for live threat data
- **Collaborative Analysis** features for team workflows
- **Advanced Reporting** with customizable templates

### **Integration Opportunities**
- **SIEM Integration** for automated analysis
- **Threat Intelligence Platforms** for data sharing
- **Incident Response Tools** for workflow automation
- **Security Orchestration** platforms for process integration

## 📚 References & Resources

### **Original AskJOE Project**
- [AskJOE Repository](https://github.com/securityjoes/AskJOE)
- [Original Documentation](https://github.com/securityjoes/AskJOE#readme)
- [Author: @moval0x1](https://twitter.com/moval0x1)

### **Integrated Services**
- [VirusTotal API](https://developers.virustotal.com/)
- [Hybrid Analysis](https://www.hybrid-analysis.com/)
- [AlienVault OTX](https://otx.alienvault.com/)
- [Malware Bazaar](https://bazaar.abuse.ch/)
- [Intezer](https://analyze.intezer.com/)
- [Any.Run](https://app.any.run/)
- [Triage](https://tria.ge/)
- [X-Force Exchange](https://exchange.xforce.ibmcloud.com/)

### **Core Technologies**
- [Ghidra](https://ghidra-sre.org/)
- [PyGhidra](https://github.com/NationalSecurityAgency/ghidra/tree/master/GhidraDev/GhidraScripts/Python)
- [Mandiant CAPA](https://github.com/mandiant/capa)
- [OpenAI API](https://platform.openai.com/)

## 📄 License

This project is licensed under the **GPL-2.0 License** - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Original AskJOE Team** for the foundational AI integration
- **Security Joes** for continued development and support
- **Open Source Community** for the tools and libraries that make this possible
- **Threat Intelligence Providers** for their valuable data and services

## 📞 Support & Contact

- **GitHub Issues**: Report bugs and request features
- **Security Joes**: [https://securityjoes.com/](https://securityjoes.com/)
- **Twitter**: [@moval0x1](https://twitter.com/moval0x1)

---

**AskJOE 2.0** - Transforming malware analysis through AI, intelligence, and automation. 🚀

*Built with ❤️ by the Security Joes team and the open source community.*

