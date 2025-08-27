# AskJOE 2.0 - Advanced Malware Analysis Suite

[![GitHub stars](https://img.shields.io/github/stars/securityjoes/AskJOE)](https://github.com/securityjoes/AskJOE/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/securityjoes/AskJOE)](https://github.com/securityjoes/AskJOE/network)
[![License](https://img.shields.io/badge/License-GPL_v2-blue.svg)](LICENSE)

> **AI-Powered Malware Analysis & Threat Intelligence for Ghidra**  
> Transform your static analysis workflow with cutting-edge AI capabilities, comprehensive malware detection, and advanced threat intelligence.
##  What is AskJOE 2.0?

AskJOE 2.0 is an evolution of the original [AskJOE project](https://github.com/securityjoes/AskJOE), transforming it from a single AI-powered function analyzer into a comprehensive malware analysis suite. Built on the foundation of Ghidra and OpenAI integration, this enhanced version adds 8 specialized analysis modules that provide deep insights into malware behavior, threat intelligence, and reverse engineering analysis.

###  Evolution from AskJOE 1.0

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

##  Core Analysis Modules

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

##  Installation & Setup

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

##  Usage Examples

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

## Contributing

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

##  References & Resources

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

##  License

This project is licensed under the **GPL-2.0 License** - see the [LICENSE](LICENSE) file for details.

##  Acknowledgments

- **Security Joes** for continued development and support
- **Open Source Community** for the tools and libraries that make this possible
- **Threat Intelligence Providers** for their valuable data and services

##  Support & Contact

- **GitHub Issues**: Report bugs and request features
- **Security Joes**: [https://securityjoes.com/](https://securityjoes.com/)
- **Twitter**: [@moval0x1](https://twitter.com/moval0x1)

---

**AskJOE 2.0** - Transforming malware analysis through AI, intelligence, and automation. 

