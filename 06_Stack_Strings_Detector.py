# AskJOE Stack Strings Detector - Detect and recover stack-based strings
# @author Charles Lomboni (charlesl[at]securityjoes[dot]com)
# @category SecurityJOES
# @keybinding CTRL SHIFT S
# @menupath Tools.SecurityJOES.Stack Strings Detector
# @runtime PyGhidra

import os
import datetime
import base64
import configparser

# Import standardized logging
from AskJOE.logging_utils import setup_logging, log_info, log_error, log_debug, log_critical

# Setup standardized logging
logger, log_file = setup_logging("stack_strings_detector")

def load_config():
    """Load configuration from config.ini"""
    try:
        config = configparser.ConfigParser()
        config_path = os.path.join(os.path.dirname(__file__), "AskJOE", "config.ini")
        
        if not config.read(config_path):
            log_error(logger, "Could not read config file: {}".format(config_path))
            return None
            
        return config
    except Exception as e:
        log_error(logger, "Error loading config: {}".format(e))
        return None

def recover_stack_string(address):
    """Recover stack strings from memory - Original working implementation from AskJOE"""
    try:
        stack_string = ""
        current_instruction = currentProgram.getListing().getInstructionAt(address)
        current_address = address

        while current_instruction and current_instruction.getScalar(1):
            scalar_value = current_instruction.getScalar(1)
            if not scalar_value:
                break
            decimal_value = scalar_value.getValue()

            try:
                next_instruction = current_instruction.getNext()
                if decimal_value == 0 and stack_string and next_instruction.getScalar(1).value == 0:
                    return stack_string, str(current_address)
            except AttributeError:
                pass

            stack_string_part = ""

            while decimal_value > 0:
                if decimal_value > 126:
                    try:
                        hex_str = hex(decimal_value)[2:]
                        bytes_array = bytes.fromhex(hex_str)
                        ascii_str = bytes_array.decode()
                        stack_string_part += ascii_str[::-1]
                        decimal_value = 0
                    except (ValueError, UnicodeDecodeError):
                        decimal_value = 0
                else:
                    stack_string_part += chr(decimal_value & 0xff)
                    decimal_value >>= 8

            stack_string += stack_string_part

            try:
                next_instruction = current_instruction.getNext()
                if next_instruction.getScalar(1) is None and next_instruction.getNext().getScalar(1) is not None:
                    current_instruction = next_instruction
            except AttributeError:
                pass

            current_instruction = current_instruction.getNext()
            current_address = current_instruction.getAddress() if current_instruction else current_address

        return stack_string, str(current_address)
    except Exception as e:
        log_error(logger, "Error recovering stack string: {}".format(e))
        return "", ""

def is_printable_ascii(s):
    """Check if string contains only printable ASCII characters"""
    try:
        if not s:
            return False
        return all(32 <= ord(c) <= 126 for c in str(s))
    except:
        return False

def calculate_string_entropy(s):
    """Calculate Shannon entropy of a string"""
    try:
        if not s:
            return 0.0
        
        # Count character frequencies
        char_counts = {}
        for char in str(s):
            char_counts[char] = char_counts.get(char, 0) + 1
        
        # Calculate entropy
        length = len(s)
        entropy = 0.0
        
        for count in char_counts.values():
            if count > 0:
                probability = count / length
                entropy -= probability * (probability.bit_length() - 1)
        
        return entropy
    except:
        return 0.0

def is_readable_string(s, config):
    """Validate if a string is readable based on configuration"""
    try:
        if not s or not config:
            return False
            
        s = str(s)
        length = len(s)
        
        if length < config.get('min_string_length', 2):
            return False
        
        # Calculate character ratios
        printable_chars = sum(1 for c in s if 32 <= ord(c) <= 126)
        alphabetic_chars = sum(1 for c in s if c.isalpha())
        numeric_chars = sum(1 for c in s if c.isdigit())
        special_chars = sum(1 for c in s if not c.isalnum() and not c.isspace())
        
        printable_ratio = (printable_chars / length) * 100 if length > 0 else 0
        alphabetic_ratio = (alphabetic_chars / length) * 100 if length > 0 else 0
        numeric_ratio = (numeric_chars / length) * 100 if length > 0 else 0
        special_ratio = (special_chars / length) * 100 if length > 0 else 0
        
        # Check printable ratio
        if printable_ratio < config.get('min_printable_ratio', 80):
            return False
        
        # Check alphabetic ratio
        if alphabetic_ratio < config.get('min_alphabetic_ratio', 30):
            return False
        
        # Filter numeric strings if enabled
        if config.get('filter_numeric_strings', True) and numeric_ratio > 70:
            return False
        
        # Filter special character strings if enabled
        if config.get('filter_special_char_strings', True) and special_ratio > 60:
            return False
        
        # Check for excessive repeated characters
        if length > 2:
            char_counts = {}
            for char in s:
                char_counts[char] = char_counts.get(char, 0) + 1
            
            max_repeated = max(char_counts.values())
            repeated_ratio = (max_repeated / length) * 100
            
            if repeated_ratio > config.get('max_repeated_ratio', 50):
                return False
        
        # Check word length for multi-word strings
        words = s.split()
        if len(words) > 1:
            min_word_len = config.get('min_word_length', 2)
            if any(len(word) < min_word_len for word in words):
                return False
        
        # Entropy-based filtering
        if config.get('enable_entropy_filtering', True):
            entropy = calculate_string_entropy(s)
            max_entropy = config.get('max_entropy_threshold', 4.5)
            if entropy > max_entropy:
                return False
        
        return True
        
    except Exception as e:
        log_debug(logger, "Error validating string '{}': {}".format(s, e))
        return False

def detect_string_type(data):
    """Detect the type of string data"""
    try:
        if not data:
            return "EMPTY"
            
        if isinstance(data, str):
            # Check for WIDE (Unicode) strings
            if any(ord(c) > 127 for c in data):
                return "WIDE"
            # Check for ASCII
            elif is_printable_ascii(data):
                return "ASCII"
            else:
                return "UNKNOWN"
        elif isinstance(data, bytes):
            # Try UTF-16LE
            try:
                data.decode('utf-16le')
                return "UTF-16LE"
            except:
                pass
            # Try UTF-16BE
            try:
                data.decode('utf-16be')
                return "UTF-16BE"
            except:
                pass
            # Try UTF-8
            try:
                data.decode('utf-8')
                return "UTF-8"
            except:
                pass
        return "UNKNOWN"
    except:
        return "UNKNOWN"

def detect_stack_strings(operation):
    """Detect stack-based strings in the program using the original working implementation"""
    try:
        log_info(logger, "Starting stack strings detection")
        println("[+] AskJOE Stack Strings Detection: {}".format(operation))
        
        # Load configuration
        config = load_config()
        if config and 'STACK_STRINGS' in config:
            min_string_length = config.getint('STACK_STRINGS', 'min_string_length', fallback=2)
            max_strings_per_type = config.getint('STACK_STRINGS', 'max_strings_per_type', fallback=0)
            enable_detailed_analysis = config.getboolean('STACK_STRINGS', 'enable_detailed_analysis', fallback=True)
            
            # Get validation settings
            validation_config = {
                'min_string_length': min_string_length,
                'min_printable_ratio': config.getint('STACK_STRINGS', 'min_printable_ratio', fallback=80),
                'min_alphabetic_ratio': config.getint('STACK_STRINGS', 'min_alphabetic_ratio', fallback=30),
                'max_repeated_ratio': config.getint('STACK_STRINGS', 'max_repeated_ratio', fallback=50),
                'filter_numeric_strings': config.getboolean('STACK_STRINGS', 'filter_numeric_strings', fallback=True),
                'filter_special_char_strings': config.getboolean('STACK_STRINGS', 'filter_special_char_strings', fallback=True),
                'min_word_length': config.getint('STACK_STRINGS', 'min_word_length', fallback=2),
                'enable_entropy_filtering': config.getboolean('STACK_STRINGS', 'enable_entropy_filtering', fallback=True),
                'max_entropy_threshold': config.getfloat('STACK_STRINGS', 'max_entropy_threshold', fallback=4.5)
            }
        else:
            min_string_length = 2
            max_strings_per_type = 0
            enable_detailed_analysis = True
            validation_config = {
                'min_string_length': 2,
                'min_printable_ratio': 80,
                'min_alphabetic_ratio': 30,
                'max_repeated_ratio': 50,
                'filter_numeric_strings': True,
                'filter_special_char_strings': True,
                'min_word_length': 2,
                'enable_entropy_filtering': True,
                'max_entropy_threshold': 4.5
            }
            
        println("[+] Configuration: min_length={}, max_per_type={}, detailed_analysis={}".format(
            min_string_length, max_strings_per_type, enable_detailed_analysis))
        println("[+] Validation: printable_ratio>={}%, alphabetic_ratio>={}%, entropy<={}".format(
            validation_config['min_printable_ratio'], validation_config['min_alphabetic_ratio'], validation_config['max_entropy_threshold']))
        
        # Get current program
        if not currentProgram:
            error_msg = "No program loaded"
            log_error(logger, error_msg)
            println("[-] {}".format(error_msg))
            return
        
        # Get listing and instructions
        listing = currentProgram.getListing()
        instructions = listing.getInstructions(True)
        
        stack_strings = []
        total_candidates = 0
        filtered_out = 0
        log_info(logger, "Scanning instructions for stack strings...")
        
        while instructions.hasNext():
            instruction = instructions.next()
            
            # Look for stack operations that might contain strings
            mnemonic = instruction.getMnemonicString()
            
            if mnemonic in ['PUSH', 'MOV']:
                # Check if this instruction has a scalar operand that could be a string
                try:
                    if instruction.getScalar(1):
                        scalar_value = instruction.getScalar(1)
                        if scalar_value and scalar_value.getValue() > 0:
                            total_candidates += 1
                            
                            # Try to recover the complete stack string starting from this address
                            recovered_string, end_address = recover_stack_string(instruction.getAddress())
                            
                            if recovered_string and len(recovered_string) >= min_string_length:
                                # Validate if the string is readable
                                if is_readable_string(recovered_string, validation_config):
                                    # Analyze the recovered string
                                    string_type = detect_string_type(recovered_string)
                                    
                                    stack_strings.append({
                                        'address': instruction.getAddress(),
                                        'instruction': str(instruction),
                                        'recovered': recovered_string,
                                        'string_type': string_type,
                                        'end_address': end_address
                                    })
                                    
                                    # Add comment to instruction
                                    try:
                                        code_unit = listing.getCodeUnitAt(instruction.getAddress())
                                        if code_unit:
                                            comment = "Stack String: {} ({})".format(
                                                recovered_string[:50] + "..." if len(recovered_string) > 50 else recovered_string,
                                                string_type
                                            )
                                            code_unit.setComment(code_unit.EOL_COMMENT, comment)
                                    except Exception as comment_error:
                                        log_debug(logger, "Error adding comment: {}".format(comment_error))
                                        pass
                                else:
                                    filtered_out += 1
                                    
                except Exception as e:
                    log_debug(logger, "Error processing instruction: {}".format(e))
                    continue
        
        # Display results
        if stack_strings:
            println("=" * 80)
            println("STACK STRINGS DETECTION RESULTS")
            println("=" * 80)
            
            # Show validation statistics
            println("\nVALIDATION STATISTICS:")
            println("  Total candidates found: {}".format(total_candidates))
            println("  Strings filtered out: {}".format(filtered_out))
            println("  Valid strings remaining: {}".format(len(stack_strings)))
            println("  Filter rate: {:.1f}%".format((filtered_out / total_candidates * 100) if total_candidates > 0 else 0))
            
            # Group by string type
            by_type = {}
            for ss in stack_strings:
                string_type = ss['string_type']
                if string_type not in by_type:
                    by_type[string_type] = []
                by_type[string_type].append(ss)
            
            # Display by type
            for string_type in sorted(by_type.keys()):
                println("\n  {} Strings:".format(string_type))
                type_strings = by_type[string_type]
                
                # Show all strings or limit based on config
                strings_to_show = type_strings
                if max_strings_per_type > 0:
                    strings_to_show = type_strings[:max_strings_per_type]
                
                for i, ss in enumerate(strings_to_show):
                    println("  {}. 0x{} -> {} ({})".format(
                        i + 1,
                        ss['address'],
                        ss['recovered'][:50] + "..." if len(ss['recovered']) > 50 else ss['recovered'],
                        ss['string_type']
                    ))
                
                # Show count if we limited the display
                if max_strings_per_type > 0 and len(type_strings) > max_strings_per_type:
                    println("     ... and {} more {} strings".format(len(type_strings) - max_strings_per_type, string_type))
                elif max_strings_per_type == 0:
                    # Show total count when displaying all
                    println("     Total: {} {} strings".format(len(type_strings), string_type))
            
            println("\nSUMMARY:")
            println("  Total stack strings found: {}".format(len(stack_strings)))
            for string_type, strings in by_type.items():
                println("  {} strings: {}".format(string_type, len(strings)))
            
            println("=" * 80)
            
            log_info(logger, "Stack strings detection completed. Found {} valid strings out of {} candidates".format(
                len(stack_strings), total_candidates))
        else:
            println("[-] No valid stack strings detected")
            if total_candidates > 0:
                println("[!] {} candidates were found but filtered out due to validation criteria")
                println("[!] Consider adjusting validation settings in config.ini")
            log_info(logger, "No valid stack strings detected out of {} candidates".format(total_candidates))
        
    except Exception as e:
        error_msg = "Stack strings detection failed: {}".format(str(e))
        log_error(logger, error_msg, exc_info=True)
        println("[-] {}".format(error_msg))

def run():
    """Main execution function"""
    try:
        log_info(logger, "Starting Stack Strings Detector script")
        println("Starting Stack Strings Detector...")
        monitor.setMessage("AskJOE Stack Strings Detector is running")
        
        detect_stack_strings("Stack Strings Detection")
        
        log_info(logger, "Stack Strings Detector script completed successfully")
        println("Stack Strings Detector completed successfully!")
        
    except Exception as ex:
        error_msg = "Stack Strings Detector script failed: {}".format(str(ex))
        log_error(logger, error_msg, exc_info=True)
        println("[-] {}".format(error_msg))

try:
    run()
except Exception as ex:
    error_msg = "Critical error in Stack Strings Detector script: {}".format(str(ex))
    log_critical(logger, error_msg, exc_info=True)
    println("[-] {}".format(error_msg))
