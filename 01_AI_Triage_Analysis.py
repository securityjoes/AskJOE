# AskJOE AI Triage Analysis - Automated malware analysis using AI
# @author Charles Lomboni (charlesl[at]securityjoes[dot]com)
# @category SecurityJOES
# @keybinding CTRL SHIFT A
# @menupath Tools.SecurityJOES.AI Triage Analysis
# @runtime PyGhidra

import os
import datetime

# Import standardized logging
from AskJOE.logging_utils import setup_logging, log_info, log_error, log_critical, log_debug, log_warning

# Setup standardized logging
logger, log_file = setup_logging("ai_triage")

def format_ai_response(response_text):
    """Format the AI response in a user-friendly way"""
    try:
        # Split the response into lines
        lines = response_text.strip().split('\n')
        formatted_lines = []
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
                
            # Format numbered points with better spacing
            if line.startswith('1.'):
                formatted_lines.append("")
                formatted_lines.append("  " + line)
            elif line.startswith('2.'):
                formatted_lines.append("")
                formatted_lines.append("  " + line)
            elif line.startswith('3.'):
                formatted_lines.append("")
                formatted_lines.append("  " + line)
            elif line.startswith('4.'):
                formatted_lines.append("")
                formatted_lines.append("  " + line)
            # Format sub-points or key indicators
            elif line.startswith('-') or line.startswith('•'):
                formatted_lines.append("   " + line)
            # Format other content
            else:
                formatted_lines.append(line)
        
        return '\n'.join(formatted_lines)
        
    except Exception as e:
        # If formatting fails, return original response
        return response_text


def extract_comprehensive_triage_data():
    """Extract comprehensive technical data for AI triage analysis"""
    try:
        triage_data = {}
        
        # 1. Basic PE Facts & Hashes
        println("[+] Extracting basic PE information...")
        triage_data["basic_info"] = extract_basic_pe_info()
        
        # 2. Imports (grouped by category)
        println("[+] Analyzing imports and dependencies...")
        triage_data["imports"] = extract_imports_analysis()
        
        # 3. Sections & characteristics
        println("[+] Analyzing PE sections...")
        triage_data["sections"] = extract_sections_analysis()
        
        # 4. Version info
        println("[+] Extracting version information...")
        triage_data["version_info"] = extract_version_info()
        
        # 5. Stable strings (filtered for relevance)
        println("[+] Collecting stable strings...")
        triage_data["stable_strings"] = extract_stable_strings()
        
        # 6. Code signatures (hex patterns)
        println("[+] Extracting code signatures...")
        triage_data["code_signatures"] = extract_code_signatures()
        
        # 7. Optional advanced indicators
        println("[+] Extracting advanced indicators...")
        triage_data["advanced_indicators"] = extract_advanced_indicators()
        
        return triage_data
        
    except Exception as e:
        log_error(logger, "Error extracting triage data: {}".format(e))
        return {}

def extract_basic_pe_info():
    """Extract basic PE information and hashes"""
    try:
        info = {}
        
        # Get program info
        program = currentProgram
        
        # Try to get actual file hash or generate a unique identifier
        try:
            # Try to get file path and calculate hash
            file_path = program.getExecutablePath()
            if file_path and os.path.exists(file_path):
                import hashlib
                with open(file_path, 'rb') as f:
                    file_content = f.read()
                    info["sha256"] = hashlib.sha256(file_content).hexdigest()
            else:
                # Generate a unique identifier based on program properties
                program_id = str(program.getEntryPoint()) + str(program.getMaxAddress()) + str(program.getLanguage())
                info["sha256"] = hashlib.sha256(program_id.encode()).hexdigest()[:16]
        except:
            # Fallback to timestamp-based identifier
            info["sha256"] = "unknown_{}".format(int(datetime.datetime.now().timestamp()))
        
        info["file_size"] = program.getMaxAddress().getOffset()
        info["architecture"] = "x64" if program.getLanguage().getLanguageDescription().getSize() == 8 else "x86"
        
        # Get PE header info
        try:
            from ghidra.app.util.bin import PeCoffFileHeader
            from ghidra.app.util.bin import PeCoffFileHeaderReader
            
            # Try to get compile timestamp
            info["compile_timestamp"] = "N/A"
            try:
                # This is a simplified approach - in real implementation you'd parse PE header
                info["compile_timestamp"] = "Unknown"
            except:
                pass
            
            # Get subsystem info
            info["subsystem"] = "Unknown"
            try:
                # Simplified subsystem detection
                if "GUI" in str(program.getLanguage().getLanguageDescription()):
                    info["subsystem"] = "GUI"
                else:
                    info["subsystem"] = "Console"
            except:
                pass
                
        except Exception as e:
            log_debug(logger, "Could not extract detailed PE info: {}".format(e))
            info["compile_timestamp"] = "N/A"
            info["subsystem"] = "Unknown"
        
        # Add more detailed information
        try:
            # Get entry point
            entry_point = program.getEntryPoint()
            if entry_point:
                info["entry_point"] = str(entry_point)
            
            # Get function count
            function_manager = program.getFunctionManager()
            if function_manager:
                functions = function_manager.getFunctions(True)
                info["function_count"] = len(list(functions))
            
            # Get data count
            listing = program.getListing()
            if listing:
                data_iterator = listing.getDefinedData(True)
                info["data_count"] = len(list(data_iterator))
            
            # Get string count
            strings = extract_stable_strings()
            if strings and not isinstance(strings, dict):
                info["string_count"] = len(strings)
            
        except Exception as e:
            log_debug(logger, "Could not extract additional PE info: {}".format(e))
        
        return info
        
    except Exception as e:
        log_error(logger, "Error extracting basic PE info: {}".format(e))
        return {"error": str(e)}

def extract_imports_analysis():
    """Extract and categorize imports"""
    try:
        imports = {}
        
        # Get import table
        symbol_table = currentProgram.getSymbolTable()
        import_symbols = symbol_table.getSymbols("EXTERNAL")
        
        # Categorize imports
        categories = {
            "network": ["WinInet", "WinHTTP", "ws2_32", "iphlpapi", "wsock32", "wininet", "winhttp"],
            "crypto": ["crypt32", "bcrypt", "advapi32", "cryptui", "ncrypt"],
            "system": ["kernel32", "ntdll", "user32", "gdi32", "shell32", "ole32", "oleaut32"],
            "registry": ["advapi32", "shlwapi", "regapi"],
            "file": ["kernel32", "msvcrt", "ntdll"],
            "process": ["kernel32", "psapi", "tlhelp32", "ntdll"],
            "wmi": ["wbem", "ole32", "oleaut32", "wbemcli"],
            "com": ["ole32", "oleaut32", "comctl32", "comdlg32"],
            "scheduling": ["taskschd", "advapi32", "kernel32"],
            "memory": ["kernel32", "ntdll", "msvcrt"],
            "other": []
        }
        
        categorized_imports = {cat: [] for cat in categories.keys()}
        
        for symbol in import_symbols:
            if symbol.getSource() == ghidra.program.model.symbol.SourceType.IMPORTED:
                symbol_name = symbol.getName()
                library_name = symbol.getParentNamespace().getName()
                
                # Categorize the import
                categorized = False
                for category, keywords in categories.items():
                    if any(keyword.lower() in library_name.lower() for keyword in keywords):
                        categorized_imports[category].append("{}!{}".format(library_name, symbol_name))
                        categorized = True
                        break
                
                if not categorized:
                    categorized_imports["other"].append("{}!{}".format(library_name, symbol_name))
        
        # Filter out empty categories and limit results
        for category in list(categorized_imports.keys()):
            if not categorized_imports[category]:
                del categorized_imports[category]
            else:
                # Limit to top 10 imports per category
                categorized_imports[category] = categorized_imports[category][:10]
        
        return categorized_imports
        
    except Exception as e:
        log_error(logger, "Error extracting imports: {}".format(e))
        return {"error": str(e)}

def extract_sections_analysis():
    """Extract PE sections with characteristics"""
    try:
        sections = []
        
        # Get memory blocks (simplified section analysis)
        memory_blocks = currentProgram.getMemory().getBlocks()
        
        for block in memory_blocks:
            if block.isInitialized():
                section_info = {
                    "name": block.getName(),
                    "size": block.getSize(),
                    "entropy": "N/A",  # Will calculate below
                    "characteristics": []
                }
                
                # Calculate actual entropy for the section
                try:
                    # Get section data for entropy calculation
                    start_addr = block.getStart()
                    end_addr = block.getEnd()
                    
                    # Read section data (limit to first 1MB to avoid memory issues)
                    max_size = min(block.getSize(), 1024 * 1024)
                    section_data = []
                    
                    current_addr = start_addr
                    bytes_read = 0
                    
                    while current_addr.compareTo(end_addr) < 0 and bytes_read < max_size:
                        try:
                            byte_val = currentProgram.getMemory().getByte(current_addr)
                            if byte_val is not None:
                                section_data.append(byte_val)
                            bytes_read += 1
                            current_addr = current_addr.add(1)
                        except:
                            break
                    
                    # Calculate entropy
                    if section_data:
                        section_info["entropy"] = calculate_entropy(section_data)
                    else:
                        section_info["entropy"] = "N/A"
                        
                except Exception as e:
                    log_debug(logger, "Could not calculate entropy for section {}: {}".format(block.getName(), e))
                    section_info["entropy"] = "N/A"
                
                # Determine characteristics using correct Ghidra API
                try:
                    # Check if block has executable permissions
                    if hasattr(block, 'getPermissions'):
                        permissions = block.getPermissions()
                        if permissions and permissions.isExecute():
                            section_info["characteristics"].append("executable")
                    else:
                        # Fallback: check if block name suggests executable
                        if ".text" in block.getName().lower():
                            section_info["characteristics"].append("executable")
                    
                    # Check if block has write permissions
                    if hasattr(block, 'getPermissions'):
                        permissions = block.getPermissions()
                        if permissions and permissions.isWrite():
                            section_info["characteristics"].append("writable")
                    else:
                        # Fallback: check if block name suggests writable
                        if ".data" in block.getName().lower():
                            section_info["characteristics"].append("writable")
                    
                    # Most blocks are readable
                    section_info["characteristics"].append("readable")
                    
                except Exception as perm_error:
                    log_debug(logger, "Could not determine permissions for block {}: {}".format(block.getName(), perm_error))
                    # Add basic characteristics based on block name
                    if ".text" in block.getName().lower():
                        section_info["characteristics"].append("executable")
                    if ".data" in block.getName().lower():
                        section_info["characteristics"].append("writable")
                    section_info["characteristics"].append("readable")
                
                sections.append(section_info)
        
        return sections[:10]  # Limit to 10 sections
        
    except Exception as e:
        log_error(logger, "Error extracting sections: {}".format(e))
        return {"error": str(e)}

def calculate_entropy(data_block):
    """Calculate Shannon entropy of a data block"""
    try:
        if not data_block or len(data_block) == 0:
            return 0.0
        
        # Count frequency of each byte value
        byte_counts = {}
        total_bytes = len(data_block)
        
        for byte in data_block:
            if isinstance(byte, str):
                byte_val = ord(byte)
            else:
                byte_val = byte
            byte_counts[byte_val] = byte_counts.get(byte_val, 0) + 1
        
        # Calculate Shannon entropy: H = -sum(p * log2(p))
        entropy = 0.0
        for count in byte_counts.values():
            if count > 0:
                probability = count / total_bytes
                entropy -= probability * (probability.bit_length() - 1)  # log2 approximation
        
        return round(entropy, 2)
        
    except Exception as e:
        log_debug(logger, "Error calculating entropy: {}".format(e))
        return 0.0

def extract_version_info():
    """Extract version information from PE resources"""
    try:
        version_info = {}
        
        # Initialize with default values
        version_patterns = ["CompanyName", "FileDescription", "ProductName", "OriginalFilename", "LegalCopyright", 
                           "FileVersion", "ProductVersion", "InternalName"]
        for pattern in version_patterns:
            version_info[pattern] = "Not found"
        
        # Try to get version info from PE resources
        try:
            from ghidra.app.util.bin import PeCoffFileHeader
            from ghidra.app.util.bin import PeCoffFileHeaderReader
            
            # Get program info
            program = currentProgram
            if program:
                # Look for version strings in the program
                strings = []
                dataIterator = program.getListing().getDefinedData(True)
                
                while dataIterator.hasNext():
                    data = dataIterator.next()
                    try:
                        string_value = data.getDefaultValueRepresentation()
                        if string_value and len(string_value) > 3:
                            strings.append(string_value)
                    except:
                        continue
                
                # Search for version patterns in strings
                for string in strings:
                    string_lower = string.lower()
                    
                    # Company name patterns
                    if any(pattern in string_lower for pattern in ["company", "corp", "inc", "ltd", "llc"]):
                        if "companyname" not in version_info or version_info["CompanyName"] == "Not found":
                            version_info["CompanyName"] = string
                    
                    # File description patterns
                    if any(pattern in string_lower for pattern in ["description", "desc", "info", "details"]):
                        if "filedescription" not in version_info or version_info["FileDescription"] == "Not found":
                            version_info["FileDescription"] = string
                    
                    # Product name patterns
                    if any(pattern in string_lower for pattern in ["product", "app", "software", "tool"]):
                        if "productname" not in version_info or version_info["ProductName"] == "Not found":
                            version_info["ProductName"] = string
                    
                    # Original filename patterns
                    if any(pattern in string_lower for pattern in ["original", "source", "file"]):
                        if "originalfilename" not in version_info or version_info["OriginalFilename"] == "Not found":
                            version_info["OriginalFilename"] = string
                    
                    # Copyright patterns
                    if any(pattern in string_lower for pattern in ["copyright", "©", "copr", "legal"]):
                        if "legalcopyright" not in version_info or version_info["LegalCopyright"] == "Not found":
                            version_info["LegalCopyright"] = string
                    
                    # Version patterns
                    if any(pattern in string_lower for pattern in ["version", "ver", "v "]):
                        if "fileversion" not in version_info or version_info["FileVersion"] == "Not found":
                            version_info["FileVersion"] = string
                        elif "productversion" not in version_info or version_info["ProductVersion"] == "Not found":
                            version_info["ProductVersion"] = string
                
                # Try to get internal name from entry point or function names
                try:
                    entry_point = program.getEntryPoint()
                    if entry_point:
                        function_manager = program.getFunctionManager()
                        func = function_manager.getFunctionContaining(entry_point)
                        if func:
                            func_name = func.getName()
                            if func_name and func_name != "entry":
                                version_info["InternalName"] = func_name
                except:
                    pass
                    
        except Exception as e:
            log_debug(logger, "Could not extract detailed version info: {}".format(e))
        
        return version_info
        
    except Exception as e:
        log_error(logger, "Error extracting version info: {}".format(e))
        return {"error": str(e)}

def extract_stable_strings():
    """Extract stable strings relevant for malware analysis"""
    try:
        stable_strings = []
        
        # Get all strings
        dataIterator = currentProgram.getListing().getDefinedData(True)
        
        while dataIterator.hasNext():
            data = dataIterator.next()
            try:
                string_value = data.getDefaultValueRepresentation()
                if string_value and len(string_value) > 3:
                    # Filter for stable, relevant strings
                    if is_stable_string(string_value):
                        stable_strings.append(string_value)
            except:
                continue
        
        # Return top 20-30 most relevant strings
        return stable_strings[:30]
        
    except Exception as e:
        log_error(logger, "Error extracting stable strings: {}".format(e))
        return {"error": str(e)}

def is_stable_string(string_value):
    """Determine if a string is stable and relevant for malware analysis"""
    try:
        # Skip volatile content
        volatile_patterns = [
            "C:\\Users\\", "C:\\Program Files\\", "C:\\Windows\\",
            "\\AppData\\", "\\Temp\\", "\\tmp\\",
            "username", "user", "admin", "administrator"
        ]
        
        for pattern in volatile_patterns:
            if pattern.lower() in string_value.lower():
                return False
        
        # Look for relevant patterns
        relevant_patterns = [
            "http://", "https://", "ftp://", "smtp://",
            "mutex", "pipe", "registry", "reg",
            "config", "setting", "key", "value",
            "user-agent", "useragent", "mozilla",
            "error", "exception", "failed", "success",
            "download", "upload", "connect", "send", "receive",
            "encrypt", "decrypt", "hash", "md5", "sha",
            "inject", "hook", "bypass", "evade"
        ]
        
        for pattern in relevant_patterns:
            if pattern.lower() in string_value.lower():
                return True
        
        # Include strings that look like configuration or technical data
        if any(char in string_value for char in "{}[]()<>:;,.="):
            return True
        
        return False
        
    except:
        return False

def extract_code_signatures():
    """Extract distinctive code signatures (hex patterns)"""
    try:
        signatures = []
        
        # Get function manager
        function_manager = currentProgram.getFunctionManager()
        functions = function_manager.getFunctions(True)
        
        # Look for distinctive functions (simplified approach)
        count = 0
        for function in functions:
            if count >= 3:  # Limit to 3 signatures
                break
                
            try:
                # Get function body
                body = function.getBody()
                if body:
                    # Create a simple signature from function start
                    start_addr = body.getMinAddress()
                    code_unit = currentProgram.getListing().getCodeUnitAt(start_addr)
                    
                    if code_unit:
                        # Extract first few bytes as signature
                        signature = extract_hex_signature(start_addr, 16)
                        if signature:
                            signatures.append({
                                "function": function.getName(),
                                "address": str(start_addr),
                                "signature": signature
                            })
                            count += 1
            except:
                continue
        
        return signatures
        
    except Exception as e:
        log_error(logger, "Error extracting code signatures: {}".format(e))
        return {"error": str(e)}

def extract_hex_signature(address, length):
    """Extract hex signature from memory"""
    try:
        signature = []
        for i in range(length):
            try:
                byte = currentProgram.getMemory().getByte(address.add(i))
                signature.append("{:02x}".format(byte & 0xFF))
            except:
                signature.append("??")
        return " ".join(signature)
    except:
        return "N/A"

def extract_advanced_indicators():
    """Extract advanced malware indicators and packer detection"""
    try:
        indicators = {}
        
        # Check for packer indicators
        indicators["packer_indicators"] = detect_packers()
        
        # Check for suspicious characteristics
        indicators["suspicious_characteristics"] = detect_suspicious_characteristics()
        
        # Check for anti-analysis techniques
        indicators["anti_analysis"] = detect_anti_analysis()
        
        # Check for code obfuscation
        indicators["obfuscation"] = detect_obfuscation()
        
        return indicators
        
    except Exception as e:
        log_error(logger, "Error extracting advanced indicators: {}".format(e))
        return {"error": str(e)}

def detect_packers():
    """Detect common packers and protectors"""
    try:
        packer_indicators = []
        
        # Get program strings
        strings = []
        dataIterator = currentProgram.getListing().getDefinedData(True)
        while dataIterator.hasNext():
            try:
                data = dataIterator.next()
                string_value = data.getDefaultValueRepresentation()
                if string_value and len(string_value) > 3:
                    strings.append(string_value.lower())
            except:
                continue
        
        # Common packer signatures
        packer_signatures = {
            "UPX": ["upx", "upx0", "upx1", "upx!"],
            "Themida": ["themida", "themida!", "themida2"],
            "VMProtect": ["vmprotect", "vmprotect!", "vmp"],
            "ASPack": ["aspack", "aspack!", "aspack2"],
            "PECompact": ["pecompact", "pec1", "pec2"],
            "Armadillo": ["armadillo", "armadillo!", "arm"],
            "Obsidium": ["obsidium", "obsidium!", "obs"],
            "Enigma": ["enigma", "enigma!", "enig"],
            "MoleBox": ["molebox", "molebox!", "mole"],
            "Petite": ["petite", "petite!", "pet"]
        }
        
        for packer_name, signatures in packer_signatures.items():
            for sig in signatures:
                if any(sig in s for s in strings):
                    packer_indicators.append(packer_name)
                    break
        
        return packer_indicators
        
    except Exception as e:
        log_debug(logger, "Error detecting packers: {}".format(e))
        return []

def detect_suspicious_characteristics():
    """Detect suspicious program characteristics"""
    try:
        suspicious = []
        
        # Check for unusual section characteristics
        try:
            memory_blocks = currentProgram.getMemory().getBlocks()
            for block in memory_blocks:
                if block.getPermissions().isExecute() and block.getPermissions().isWrite():
                    suspicious.append("Executable and writable section: {}".format(block.getName()))
        except:
            pass
        
        # Check for unusual entry point
        try:
            entry_point = currentProgram.getEntryPoint()
            if entry_point:
                entry_offset = entry_point.getOffset()
                if entry_offset > 0x1000:  # Unusual entry point
                    suspicious.append("Unusual entry point at offset: 0x{:x}".format(entry_offset))
        except:
            pass
        
        # Check for missing imports
        try:
            symbol_table = currentProgram.getSymbolTable()
            import_symbols = symbol_table.getSymbols("EXTERNAL")
            if len(list(import_symbols)) < 5:  # Very few imports
                suspicious.append("Very few imports ({}), possible packed/obfuscated binary".format(len(list(import_symbols))))
        except:
            pass
        
        return suspicious
        
    except Exception as e:
        log_debug(logger, "Error detecting suspicious characteristics: {}".format(e))
        return []

def detect_anti_analysis():
    """Detect anti-analysis and anti-debugging techniques"""
    try:
        anti_analysis = []
        
        # Get program strings
        strings = []
        dataIterator = currentProgram.getListing().getDefinedData(True)
        while dataIterator.hasNext():
            try:
                data = dataIterator.next()
                string_value = data.getDefaultValueRepresentation()
                if string_value and len(string_value) > 3:
                    strings.append(string_value.lower())
            except:
                continue
        
        # Anti-analysis string patterns
        anti_patterns = {
            "Anti-Debug": ["debugger", "debug", "ollydbg", "x64dbg", "ida", "ghidra", "windbg"],
            "Anti-VM": ["vmware", "vbox", "virtualbox", "qemu", "xen", "hyperv"],
            "Anti-Sandbox": ["sandbox", "cuckoo", "anubis", "joesandbox", "anyrun"],
            "Timing Checks": ["sleep", "delay", "timer", "clock", "gettickcount"],
            "Process Checks": ["tasklist", "taskmgr", "process", "procmon", "procexp"]
        }
        
        for category, patterns in anti_patterns.items():
            for pattern in patterns:
                if any(pattern in s for s in strings):
                    anti_analysis.append("{}: {}".format(category, pattern))
                    break
        
        return anti_analysis
        
    except Exception as e:
        log_debug(logger, "Error detecting anti-analysis: {}".format(e))
        return []

def detect_obfuscation():
    """Detect code obfuscation techniques"""
    try:
        obfuscation = []
        
        # Check for XOR patterns in code
        try:
            function_manager = currentProgram.getFunctionManager()
            functions = function_manager.getFunctions(True)
            
            xor_count = 0
            for func in functions:
                if func.getBody():
                    for block in func.getBody():
                        for instruction in block:
                            mnemonic = instruction.getMnemonicString()
                            if mnemonic == "XOR":
                                xor_count += 1
                                if xor_count > 10:  # High XOR count suggests obfuscation
                                    obfuscation.append("High XOR instruction count: {}".format(xor_count))
                                    break
                        if xor_count > 10:
                            break
                    if xor_count > 10:
                        break
        except:
            pass
        
        # Check for unusual string patterns
        try:
            strings = []
            dataIterator = currentProgram.getListing().getDefinedData(True)
            while dataIterator.hasNext():
                try:
                    data = dataIterator.next()
                    string_value = data.getDefaultValueRepresentation()
                    if string_value and len(string_value) > 3:
                        strings.append(string_value)
                except:
                    continue
            
            # Look for obfuscated strings
            obfuscated_count = 0
            for s in strings:
                if len(s) > 10 and not any(c.isprintable() for c in s[:10]):
                    obfuscated_count += 1
            
            if obfuscated_count > 5:
                obfuscation.append("Multiple obfuscated strings detected: {}".format(obfuscated_count))
        except:
            pass
        
        return obfuscation
        
    except Exception as e:
        log_debug(logger, "Error detecting obfuscation: {}".format(e))
        return []

def ai_triage():
    """Perform AI-powered triage analysis of the current program"""
    try:
        println("[+] Starting comprehensive AI Triage analysis...")
        println("[+] Operation: AI Triage")
        
        # Get monitor for progress updates
        monitor = getMonitor()
        if monitor:
            monitor.setMessage("AskJOE AI Triage: Extracting technical data...")
        
        # Extract comprehensive triage data
        triage_data = extract_comprehensive_triage_data()
        
        if monitor and monitor.isCancelled():
            println("[-] Analysis cancelled by user")
            return
        
        if not triage_data:
            println("[-] Failed to extract triage data")
            return
        
        # Create comprehensive analysis prompt
        println("[+] Creating analysis prompt...")
        analysis_prompt = create_comprehensive_prompt(triage_data)
        
        if not analysis_prompt or analysis_prompt.startswith("Error"):
            println("[-] Failed to create analysis prompt: {}".format(analysis_prompt))
            return
        
        println("[+] Analysis prompt created successfully")
        
        println("[+] Sending comprehensive technical data to AI for analysis...")
        
        # Import OpenAI utilities
        try:
            from AskJOE.openai_utils import ask_open_ai
        except ImportError as import_error:
            println("[-] Could not import AskJOE.openai_utils: {}".format(import_error))
            println("[-] This suggests the AskJOE module is not properly installed")
            return
        
        # Get AI analysis
        ai_response = ask_open_ai(analysis_prompt)
        
        if ai_response:
            try:
                # Parse the OpenAI response
                from AskJOE.openai_utils import parse_open_ai_response
                parsed_response = parse_open_ai_response(ai_response)
                
                # Format and display the response
                formatted_response = format_ai_response(parsed_response)
                
                println("=" * 80)
                println("AI TRIAGE ANALYSIS RESULTS")
                println("=" * 80)
                println(formatted_response)
                println("=" * 80)
                
                log_info(logger, "Comprehensive AI triage analysis completed successfully")
                
            except ImportError:
                # Fallback if AskJOE module not available
                println("=" * 80)
                println("AI TRIAGE ANALYSIS RESULTS")
                println("=" * 80)
                println("OpenAI Response Received (Raw)")
                println("=" * 80)
                log_info(logger, "Comprehensive AI triage analysis completed (raw response)")
                
            except Exception as parse_error:
                # Handle any other parsing errors
                log_error(logger, "Error parsing OpenAI response: {}".format(parse_error))
                println("=" * 80)
                println("AI TRIAGE ANALYSIS RESULTS")
                println("=" * 80)
                println("Error parsing AI response. Raw response type: {}".format(type(ai_response)))
                if hasattr(ai_response, 'choices') and len(ai_response.choices) > 0:
                    try:
                        raw_content = ai_response.choices[0].message.content
                        println("Raw content preview: {}".format(raw_content[:200] if raw_content else "No content"))
                    except Exception as content_error:
                        println("Could not extract content: {}".format(content_error))
                println("=" * 80)
                log_info(logger, "AI triage analysis completed with parsing error")
                
        else:
            println("[-] Failed to get AI analysis response")
            log_error(logger, "AI triage analysis failed - no response from OpenAI")

    except Exception as e:
        error_msg = "AI Triage analysis failed: {}".format(str(e))
        log_error(logger, error_msg, exc_info=True)
        println("[-] {}".format(error_msg))

def create_comprehensive_prompt(triage_data):
    """Create comprehensive prompt for AI analysis"""
    try:
        prompt = """Analyze this comprehensive technical data from a potentially malicious program for professional malware triage:

=== BASIC PE FACTS ===
SHA256: {sha256}
File Size: {file_size} bytes
Architecture: {architecture}
Compile Timestamp: {compile_timestamp}
Subsystem: {subsystem}

=== IMPORTS ANALYSIS ===
{imports_summary}

=== SECTIONS ANALYSIS ===
{sections_summary}

=== VERSION INFORMATION ===
{version_summary}

=== STABLE STRINGS (Relevant for Analysis) ===
{strings_summary}

=== CODE SIGNATURES ===
{signatures_summary}

=== ADVANCED INDICATORS ===
{advanced_summary}

Provide a PROFESSIONAL MALWARE TRIAGE ANALYSIS including:

1. THREAT ASSESSMENT: Overall risk level (Benign/Low/Medium/High/Critical) with justification
2. MALWARE FAMILY: Most likely malware family or category based on technical indicators
3. BEHAVIORAL ANALYSIS: What this malware likely does based on imports, strings, and patterns
4. KEY INDICATORS: Specific technical indicators that support your assessment
5. DETECTION EVASION: Any anti-analysis or evasion techniques observed
6. NETWORK INDICATORS: C2, exfiltration, or network behavior indicators
7. PERSISTENCE: Likely persistence mechanisms
8. RECOMMENDATIONS: Specific next steps for analysis and response
9. CONFIDENCE LEVEL: Your confidence in this assessment (High/Medium/Low)

Base your analysis ONLY on the technical data provided. Be specific and technical."""

        # Format the data for the prompt
        basic = triage_data.get("basic_info", {})
        imports = triage_data.get("imports", {})
        sections = triage_data.get("sections", [])
        version = triage_data.get("version_info", {})
        strings = triage_data.get("stable_strings", [])
        signatures = triage_data.get("code_signatures", [])
        advanced = triage_data.get("advanced_indicators", {})
        
        # Format imports
        imports_text = []
        for category, imports_list in imports.items():
            if imports_list and len(imports_list) > 0:
                # Convert slice to list to avoid unhashable type error
                try:
                    limited_imports = list(imports_list)[:5] if hasattr(imports_list, '__getitem__') else imports_list[:5]
                    imports_text.append("{}: {}".format(category.upper(), ", ".join(limited_imports)))
                except Exception as e:
                    log_debug(logger, "Error processing imports for category {}: {}".format(category, e))
                    continue
        imports_summary = "\n".join(imports_text) if imports_text else "No imports found"
        
        # Format sections
        sections_text = []
        try:
            # Convert slice to list to avoid unhashable type error
            limited_sections = list(sections)[:5] if hasattr(sections, '__getitem__') else sections[:5]
            for section in limited_sections:
                if isinstance(section, dict):
                    sections_text.append("{}: {} bytes, {} ({})".format(
                        section.get("name", "Unknown"),
                        section.get("size", 0),
                        section.get("entropy", "N/A"),
                        ", ".join(section.get("characteristics", []))
                    ))
        except Exception as e:
            log_debug(logger, "Error processing sections: {}".format(e))
            sections_text = ["Error processing sections"]
        sections_summary = "\n".join(sections_text) if sections_text else "No sections analyzed"
        
        # Format version info
        version_text = []
        for key, value in version.items():
            version_text.append("{}: {}".format(key, value))
        version_summary = "\n".join(version_text) if version_text else "No version info found"
        
        # Format strings
        try:
            # Convert slice to list to avoid unhashable type error
            limited_strings = list(strings)[:20] if hasattr(strings, '__getitem__') else strings[:20]
            strings_summary = "\n".join(limited_strings) if limited_strings else "No relevant strings found"
        except Exception as e:
            log_debug(logger, "Error processing strings: {}".format(e))
            strings_summary = "Error processing strings"
        
        # Format signatures
        signatures_text = []
        try:
            # Convert slice to list to avoid unhashable type error
            limited_signatures = list(signatures)[:3] if hasattr(signatures, '__getitem__') else signatures[:3]
            for sig in limited_signatures:
                if isinstance(sig, dict):
                    signatures_text.append("{} @ {}: {}".format(
                        sig.get("function", "Unknown"),
                        sig.get("address", "Unknown"),
                        sig.get("signature", "N/A")
                    ))
        except Exception as e:
            log_debug(logger, "Error processing signatures: {}".format(e))
            signatures_text = ["Error processing signatures"]
        signatures_summary = "\n".join(signatures_text) if signatures_text else "No code signatures extracted"
        
        # Format advanced indicators
        advanced_summary = "No advanced indicators found"
        if advanced and "error" not in advanced:
            try:
                advanced_text = []
                
                # Format packer indicators
                if "packer_indicators" in advanced and advanced["packer_indicators"]:
                    packers = ", ".join(advanced["packer_indicators"])
                    advanced_text.append("Packer Detection: {}".format(packers))
                
                # Format suspicious characteristics
                if "suspicious_characteristics" in advanced and advanced["suspicious_characteristics"]:
                    suspicious = "; ".join(advanced["suspicious_characteristics"])
                    advanced_text.append("Suspicious Characteristics: {}".format(suspicious))
                
                # Format anti-analysis
                if "anti_analysis" in advanced and advanced["anti_analysis"]:
                    anti = "; ".join(advanced["anti_analysis"])
                    advanced_text.append("Anti-Analysis: {}".format(anti))
                
                # Format obfuscation
                if "obfuscation" in advanced and advanced["obfuscation"]:
                    obf = "; ".join(advanced["obfuscation"])
                    advanced_text.append("Obfuscation: {}".format(obf))
                
                if advanced_text:
                    advanced_summary = "\n".join(advanced_text)
                else:
                    advanced_summary = "No advanced indicators detected"
                    
            except Exception as e:
                log_debug(logger, "Error formatting advanced indicators: {}".format(e))
                advanced_summary = "Error processing advanced indicators"
        
        # Debug logging
        log_debug(logger, "Formatting prompt with data:")
        log_debug(logger, "Basic: {}".format(basic))
        log_debug(logger, "Imports: {}".format(imports))
        log_debug(logger, "Sections: {}".format(sections))
        log_debug(logger, "Version: {}".format(version))
        log_debug(logger, "Strings: {}".format(strings))
        log_debug(logger, "Signatures: {}".format(signatures))
        log_debug(logger, "Advanced: {}".format(advanced))
        
        try:
            formatted_prompt = prompt.format(
                sha256=basic.get("sha256", "N/A"),
                file_size=basic.get("file_size", "N/A"),
                architecture=basic.get("architecture", "N/A"),
                compile_timestamp=basic.get("compile_timestamp", "N/A"),
                subsystem=basic.get("subsystem", "N/A"),
                imports_summary=imports_summary,
                sections_summary=sections_summary,
                version_summary=version_summary,
                strings_summary=strings_summary,
                signatures_summary=signatures_summary,
                advanced_summary=advanced_summary
            )
            return formatted_prompt
        except Exception as format_error:
            log_error(logger, "Error formatting prompt: {}".format(format_error))
            return "Error formatting analysis prompt: {}".format(format_error)
        
    except Exception as e:
        log_error(logger, "Error creating comprehensive prompt: {}".format(e))
        return "Error creating analysis prompt: {}".format(e)

def run():
    """Main execution function"""
    try:
        log_info(logger, "Starting AI Triage Analysis script")
        monitor = getMonitor()
        if monitor:
            monitor.setMessage("AskJOE AI Triage Analysis is running")
        
        ai_triage()
        
        log_info(logger, "AI Triage Analysis script completed successfully")
        println("AI Triage Analysis completed successfully!")
        
    except Exception as ex:
        error_msg = "AI Triage Analysis script failed: {}".format(str(ex))
        log_error(logger, error_msg, exc_info=True)
        println("[-] {}".format(error_msg))


try:
    run()
except Exception as ex:
    error_msg = "Critical error in AI Triage Analysis script: {}".format(str(ex))
    log_critical(logger, error_msg, exc_info=True)
    println("[-] {}".format(error_msg))
