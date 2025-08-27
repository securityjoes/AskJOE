# AskJOE Advanced XOR Searcher - Detect and analyze XOR operations and obfuscated code
# @author Charles Lomboni (charlesl[at]securityjoes[dot]com)
# @category SecurityJOES
# @keybinding CTRL SHIFT X
# @menupath Tools.SecurityJOES.Advanced XOR Searcher
# @runtime PyGhidra

import os
import datetime
import re

# Ghidra imports
from ghidra.program.model.scalar import Scalar
from ghidra.program.model.symbol import Symbol

# Import standardized logging
from AskJOE.logging_utils import setup_logging, log_info, log_error, log_debug, log_critical

# Setup standardized logging
logger, log_file = setup_logging("advanced_xor_searcher")

def decode_xor_string(data, key):
    """Decode XOR encoded string with given key"""
    try:
        if isinstance(data, str):
            # Convert hex string to bytes
            if data.startswith('0x'):
                data = data[2:]
            bytes_data = bytes.fromhex(data)
        elif isinstance(data, int):
            # Convert integer to bytes
            bytes_data = data.to_bytes((data.bit_length() + 7) // 8, 'big')
        else:
            bytes_data = data
            
        decoded = bytes(b ^ key for b in bytes_data)
        return decoded.decode('ascii', errors='ignore')
    except:
        return ""

def is_printable_ascii(text):
    """Check if text contains mostly printable ASCII characters"""
    if not text:
        return False
    printable_count = sum(1 for c in text if 32 <= ord(c) <= 126)
    return printable_count / len(text) > 0.7

def brute_force_xor_decode(scalar_value):
    """Try XOR decoding with all keys from 0x01 to 0xFF"""
    if scalar_value <= 0:
        return None, None
    
    best_result = None
    best_key = None
    best_score = 0
    
    # Try all XOR keys from 0x01 to 0xFF
    for key in range(1, 256):
        decoded = decode_xor_string(scalar_value, key)
        if decoded and len(decoded) > 2:
            # Calculate a score based on readability
            printable_ratio = sum(1 for c in decoded if 32 <= ord(c) <= 126) / len(decoded)
            alpha_ratio = sum(1 for c in decoded if c.isalpha()) / len(decoded)
            
            # Prefer strings with more letters and printable characters
            score = printable_ratio * 0.6 + alpha_ratio * 0.4
            
            if score > best_score and printable_ratio > 0.8:
                best_score = score
                best_result = decoded
                best_key = key
    
    return best_result, best_key

def go_to_address(address):
    """Navigate to the specified address in Ghidra"""
    try:
        if currentProgram:
            listing = currentProgram.getListing()
            code_unit = listing.getCodeUnitAt(address)
            if code_unit:
                # Navigate to the address
                currentProgram.getMemory().setAddress(address)
                return True
    except Exception as e:
        log_debug(logger, "Error navigating to address: {}".format(e))
    return False

def analyze_xor_operation(instruction):
    """Analyze a single XOR instruction for patterns and potential obfuscation"""
    try:
        address = instruction.getAddress()
        mnemonic = instruction.getMnemonicString()
        num_operands = instruction.getNumOperands()
        
        if mnemonic != "XOR":
            return None
            
        if num_operands != 2:
            return None
            
        operand1 = instruction.getOpObjects(0)[0]
        operand2 = instruction.getOpObjects(1)[0]
        
        # Get operand strings for comparison
        op1_str = str(operand1).upper()
        op2_str = str(operand2).upper()
        
        # Filter out self-XOR operations (XOR reg, reg) - these just clear registers to zero
        if op1_str == op2_str:
            return None
            
        # Skip XOR with zero (XOR reg, 0) - these also clear registers
        if (isinstance(operand2, Scalar) and 
            operand2.getUnsignedValue() == 0):
            return None
            
        if (isinstance(operand1, Scalar) and 
            operand1.getUnsignedValue() == 0):
            return None
        
        analysis = {
            'address': address,
            'instruction': str(instruction),
            'operand1': str(operand1),
            'operand2': str(operand2),
            'type': 'Unknown',
            'key': None,
            'decoded': None,
            'suspicious': False
        }
        
        # Analyze operand types
        if isinstance(operand2, Scalar):
            # XOR with immediate value (constant)
            scalar_value = operand2.getUnsignedValue()
            analysis['type'] = 'XOR reg, imm'
            analysis['key'] = scalar_value
            
            # Try to decode as string using brute force
            if scalar_value > 0:
                decoded, key = brute_force_xor_decode(scalar_value)
                if decoded:
                    analysis['decoded'] = "XOR-0x{:02X}: {}".format(key, decoded)
                    analysis['suspicious'] = True
                        
        elif isinstance(operand1, Scalar):
            # XOR with immediate value (constant) - operand1
            scalar_value = operand1.getUnsignedValue()
            analysis['type'] = 'XOR imm, reg'
            analysis['key'] = scalar_value
            
            # Try to decode as string using brute force
            if scalar_value > 0:
                decoded, key = brute_force_xor_decode(scalar_value)
                if decoded:
                    analysis['decoded'] = "XOR-0x{:02X}: {}".format(key, decoded)
                    analysis['suspicious'] = True
        
        else:
            # XOR between registers or memory
            if '[' in op1_str or '[' in op2_str:
                analysis['type'] = 'XOR reg, [mem]'
            else:
                analysis['type'] = 'XOR reg, reg'
            
            # Check if this could be string obfuscation
            if (isinstance(operand1, Symbol) or 
                isinstance(operand2, Symbol)):
                analysis['suspicious'] = True
        
        return analysis
        
    except Exception as e:
        log_debug(logger, "Error analyzing XOR operation: {}".format(e))
        return None

def detect_xor_loops(instructions):
    """Detect sequences of XOR operations that might indicate obfuscation"""
    try:
        xor_loops = []
        current_loop = []
        
        # Convert iterator to list for easier processing
        instruction_list = list(instructions)
        
        for i, instruction in enumerate(instruction_list):
            if instruction.getMnemonicString() == "XOR":
                # Analyze this XOR instruction
                analysis = analyze_xor_operation(instruction)
                
                # Only include XOR operations that passed analysis (not self-XOR)
                if analysis:
                    # Check if this XOR is part of a loop
                    if current_loop and i - current_loop[-1]['index'] <= 3:  # Within 3 instructions
                        current_loop.append({
                            'index': i,
                            'instruction': instruction,
                            'analysis': analysis
                        })
                    else:
                        # Start new loop
                        if len(current_loop) >= 2:  # Previous loop had at least 2 XORs
                            xor_loops.append(current_loop)
                        current_loop = [{
                            'index': i,
                            'instruction': instruction,
                            'analysis': analysis
                        }]
        
        # Don't forget the last loop
        if len(current_loop) >= 2:
            xor_loops.append(current_loop)
            
        return xor_loops
        
    except Exception as e:
        log_error(logger, "Error detecting XOR loops: {}".format(e))
        return []

def run_advanced_xor_search(operation):
    """Run advanced XOR search and analysis"""
    try:
        log_info(logger, "Starting advanced XOR search")
        println("[+] AskJOE Advanced XOR Search: {}".format(operation))
        
        # Get current program
        if not currentProgram:
            error_msg = "No program loaded"
            log_error(logger, error_msg)
            println("[-] {}".format(error_msg))
            return
        
        # Get listing and instructions
        listing = currentProgram.getListing()
        instructions = listing.getInstructions(True)
        
        log_info(logger, "Scanning for XOR operations and obfuscation patterns...")
        println("Starting Advanced XOR Searcher...")
        println("Scanning for XOR operations and obfuscation patterns...")
        
        xor_operations = []
        xor_loops = []
        
        # First pass: analyze individual XOR operations
        xor_count = 0
        all_xor_instructions = []
        while instructions.hasNext():
            instruction = instructions.next()
            if instruction.getMnemonicString() == "XOR":
                xor_count += 1
                all_xor_instructions.append(instruction)
                
                analysis = analyze_xor_operation(instruction)
                if analysis:
                    xor_operations.append(analysis)
                    log_debug(logger, "Added XOR operation: {} at 0x{}".format(
                        analysis['type'], analysis['address']))
        
        println("  Found {} XOR instructions, {} passed analysis".format(xor_count, len(xor_operations)))
        
        # Second pass: detect XOR loops
        instructions = currentProgram.getListing().getInstructions(True)
        xor_loops = detect_xor_loops(instructions)
        
        # Display results
        println("=" * 100)
        println("ADVANCED XOR ANALYSIS RESULTS")
        println("=" * 100)
        
        if xor_operations:
            println("\nINDIVIDUAL XOR OPERATIONS:")
            println("-" * 80)
            println("  Note: Copy any address (e.g., 0x00443212) and use Ctrl+G to navigate to it")
            println("-" * 80)
            for op in xor_operations:
                println("  XOR {} at 0x{}: {} {} -> {}".format(
                    op['type'],
                    op['address'],
                    op['operand1'],
                    op['operand2'],
                    op['decoded'] if op['decoded'] else "No decoded string"
                ))
                
                # Add comment to instruction if suspicious
                if op['suspicious']:
                    try:
                        code_unit = listing.getCodeUnitAt(op['address'])
                        if code_unit:
                            comment = "Suspicious XOR: {} -> {}".format(
                                op['operand1'], op['operand2']
                            )
                            if op['decoded']:
                                comment += " | Decoded: {}".format(op['decoded'])
                            code_unit.setComment(code_unit.EOL_COMMENT, comment)
                    except Exception as comment_error:
                        log_debug(logger, "Error adding comment: {}".format(comment_error))
        else:
            println("\nNo individual XOR operations found")
        
        println()
        
        if xor_loops:
            println("XOR LOOPS DETECTED:")
            println("-" * 80)
            println("  Note: Copy any address (e.g., 0x004272ee) and use Ctrl+G to navigate to it")
            println("-" * 80)
            
            # Show ALL loops without truncation
            for i, loop in enumerate(xor_loops):
                println("  Loop {}: {} XOR operations at addresses:".format(
                    i + 1, len(loop)))
                
                # Show addresses for this loop
                loop_addresses = []
                valid_analyses = []
                for xor_instr in loop:
                    if xor_instr['analysis']:
                        loop_addresses.append("0x{}".format(xor_instr['analysis']['address']))
                        valid_analyses.append(xor_instr['analysis'])
                
                if loop_addresses:
                    println("    Addresses: {}".format(" -> ".join(loop_addresses)))
                    
                    # Show detailed analysis for each XOR in the loop
                    for analysis in valid_analyses:
                        println("    XOR {} at 0x{}: {} {} -> {}".format(
                            analysis['type'],
                            analysis['address'],
                            analysis['operand1'],
                            analysis['operand2'],
                            analysis['decoded'] if analysis['decoded'] else "No decoded string"
                        ))
                        
                        # Add comment to instruction if suspicious
                        if analysis['suspicious']:
                            try:
                                code_unit = listing.getCodeUnitAt(analysis['address'])
                                if code_unit:
                                    comment = "XOR Loop {}: {} -> {}".format(
                                        i + 1, analysis['operand1'], analysis['operand2']
                                    )
                                    if analysis['decoded']:
                                        comment += " | Decoded: {}".format(analysis['decoded'])
                                    code_unit.setComment(code_unit.EOL_COMMENT, comment)
                            except Exception as comment_error:
                                log_debug(logger, "Error adding comment: {}".format(comment_error))
                else:
                    # If no valid analysis, show basic loop info
                    basic_addresses = []
                    for xor_instr in loop:
                        basic_addresses.append("0x{}".format(xor_instr['instruction'].getAddress()))
                    println("    Addresses: {}".format(" -> ".join(basic_addresses)))
                    println("    Instructions: {}".format(" -> ".join([str(xor_instr['instruction']) for xor_instr in loop])))
                
                println()  # Add spacing between loops
        else:
            println("No XOR loops detected")
        
        println("\nANALYSIS SUMMARY:")
        println("-" * 80)
        println("  Total XOR operations: {}".format(len(xor_operations)))
        println("  XOR loops detected: {}".format(len(xor_loops)))
        
        # Show suspicious XORs with their addresses
        suspicious_xors = [op for op in xor_operations if op['suspicious']]
        println("  Suspicious XORs: {} (see addresses below)".format(len(suspicious_xors)))
        
        if suspicious_xors:
            println("\nSUSPICIOUS XOR OPERATIONS:")
            println("-" * 80)
            for op in suspicious_xors:
                println("  XOR {} at 0x{}: {} {} -> {}".format(
                    op['type'],
                    op['address'],
                    op['operand1'],
                    op['operand2'],
                    op['decoded'] if op['decoded'] else "No decoded string"
                ))
        
        println("=" * 100)
        
        log_info(logger, "Advanced XOR search completed. Found {} operations, {} loops".format(
            len(xor_operations), len(xor_loops)))
        
    except Exception as e:
        error_msg = "Advanced XOR search failed: {}".format(str(e))
        log_error(logger, error_msg, exc_info=True)
        println("[-] {}".format(error_msg))

def run():
    """Main execution function"""
    try:
        log_info(logger, "Starting Advanced XOR Searcher script")
        println("Starting Advanced XOR Searcher...")
        monitor.setMessage("AskJOE Advanced XOR Searcher is running")
        
        run_advanced_xor_search("Advanced XOR Search")
        
        log_info(logger, "Advanced XOR Searcher script completed successfully")
        println("Advanced XOR Searcher completed successfully!")
        
    except Exception as ex:
        error_msg = "Advanced XOR Searcher script failed: {}".format(str(ex))
        log_error(logger, error_msg, exc_info=True)
        println("[-] {}".format(error_msg))

try:
    run()
except Exception as ex:
    error_msg = "Critical error in Advanced XOR Searcher script: {}".format(str(ex))
    log_critical(logger, error_msg, exc_info=True)
    println("[-] {}".format(error_msg))
