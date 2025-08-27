# AskJOE Crypto Detector - Detect cryptographic constants and algorithms
# @author Charles Lomboni (charlesl[at]securityjoes[dot]com)
# @category SecurityJOES
# @keybinding CTRL SHIFT D
# @menupath Tools.SecurityJOES.Crypto Detector
# @runtime PyGhidra

import os
import datetime

# Import standardized logging
from AskJOE.logging_utils import setup_logging, log_info, log_error, log_warning, log_critical

# Import AskJOE data module for comprehensive crypto detection
from AskJOE import data

# Import Ghidra modules
from ghidra.program.model.symbol import SourceType

# Setup standardized logging
logger, log_file = setup_logging("crypto_detector")

def detect_crypto_constants(operation):
    """Detect cryptographic constants in the program using AskJOE database"""
    try:
        log_info(logger, "Starting comprehensive cryptographic constant detection")
        println("[+] AskJOE Crypto Detection: {}".format(operation))
        
        symbolTable = currentProgram.getSymbolTable()
        total_detections = 0
        
        # Get crypto constants from AskJOE data module
        non_sparse_consts = data.non_sparse_consts
        sparse_consts = data.sparse_consts
        
        log_info(logger, "Analyzing {} non-sparse constants".format(len(non_sparse_consts)))
        println("[+] Analyzing {} non-sparse cryptographic constants...".format(len(non_sparse_consts)))
        
        # Process non-sparse constants (byte arrays)
        for const in non_sparse_consts:
            try:
                algorithm = const.get("algorithm", "Unknown")
                name = const.get("name", "Unknown")
                
                # Convert array to byte array if needed
                if "array" in const:
                    if const.get("size") == "B":  # Byte array
                        byte_array = bytes(const["array"])
                    elif const.get("size") == "L":  # Long array
                        byte_array = b"".join([x.to_bytes(4, 'little') for x in const["array"]])
                    else:
                        continue
                elif "byte_array" in const:
                    byte_array = const["byte_array"]
                else:
                    continue
                
                # Search for the constant in memory
                found = currentProgram.getMemory().findBytes(
                    currentProgram.getMinAddress(), byte_array, None, True, getMonitor()
                )
                
                if found:
                    labelName = "aj_crypto_{}_{}_{}".format(algorithm.lower(), name.lower(), found)
                    log_info(logger, "Found crypto constant: {} {} at {}".format(algorithm, name, found))
                    println("[+] {} {} at 0x{} -> {}".format(algorithm, name, found, labelName))
                    
                    # Create symbol
                    symbolTable.createLabel(found, labelName, SourceType.USER_DEFINED)
                    total_detections += 1
                    
                    # Add comment
                    code_unit = currentProgram.getListing().getCodeUnitAt(found)
                    if code_unit:
                        comment = "Crypto constant: {} {} ({})".format(algorithm, name, const.get("description", "No description"))
                        code_unit.setComment(code_unit.PLATE_COMMENT, comment)
                        
            except Exception as e:
                log_warning(logger, "Error processing constant {} {}: {}".format(const.get('algorithm', 'unknown'), const.get('name', 'unknown'), e))
                continue

        log_info(logger, "Analyzing {} sparse constants".format(len(sparse_consts)))
        println("[+] Analyzing {} sparse cryptographic constants...".format(len(sparse_consts)))
        
        # Process sparse constants (individual values)
        listing = currentProgram.getListing()
        instruction = listing.getInstructions(1)
        
        while instruction.hasNext():
            inst = instruction.next()
            for const in sparse_consts:
                try:
                    algorithm = const.get("algorithm", "Unknown")
                    name = const.get("name", "Unknown")
                    
                    if "array" in const:
                        # Check if any value in the array matches the instruction
                        for value in const["array"]:
                            try:
                                if str(value).upper() == str(inst.getScalar(1)).upper():
                                    labeladdr = inst.getAddress()
                                    log_info(logger, "Found sparse constant: {} {} at {}".format(algorithm, name, labeladdr))
                                    
                                    # Create label
                                    labelName = "aj_crypto_sparse_{}_{}_{}".format(algorithm.lower(), name.lower(), labeladdr)
                                    symbolTable.createLabel(labeladdr, labelName, SourceType.USER_DEFINED)
                                    
                                    println("[+] Sparse {} {} at 0x{} -> {}".format(algorithm, name, labeladdr, labelName))
                                    total_detections += 1
                                    
                                    # Add comment
                                    code_unit = listing.getCodeUnitAt(labeladdr)
                                    if code_unit:
                                        comment = "Crypto constant: {} {} ({})".format(algorithm, name, const.get("description", "No description"))
                                        code_unit.setComment(code_unit.PLATE_COMMENT, comment)
                                    
                                    break  # Found one match, move to next constant
                                    
                            except Exception as e:
                                continue
                                
                except Exception as e:
                    log_warning(logger, "Error processing sparse constant {} {}: {}".format(const.get('algorithm', 'unknown'), const.get('name', 'unknown'), e))
                    continue
                    
        # Summary
        log_info(logger, "Cryptographic constant detection completed. Found {} constants".format(total_detections))
        println("[+] Crypto detection completed successfully!")
        println("[+] Total cryptographic constants detected: {}".format(total_detections))
        
        if total_detections > 0:
            println("[+] Symbols created in Symbol Tree with 'aj_crypto_' prefix")
            println("[+] Check the Symbol Tree for detailed crypto analysis")
        else:
            println("[!] No cryptographic constants detected in this sample")
            println("[+] This may indicate:")
            println("    - No crypto algorithms used")
            println("    - Constants are obfuscated/encoded")
            println("    - Crypto functions are dynamically loaded")
        
    except Exception as e:
        error_msg = "Cryptographic constant detection failed: {}".format(str(e))
        log_error(logger, error_msg, exc_info=True)
        println("[-] {}".format(error_msg))

def run():
    """Main execution function"""
    try:
        log_info(logger, "Starting Crypto Detector script")
        monitor.setMessage("AskJOE Crypto Detector is running")
        
        detect_crypto_constants("Crypto Detection")
        
        log_info(logger, "Crypto Detector script completed successfully")
        println("Crypto Detector completed successfully!")
        
    except Exception as ex:
        error_msg = "Crypto Detector script failed: {}".format(str(ex))
        log_error(logger, error_msg, exc_info=True)
        println("[-] {}".format(error_msg))

try:
    run()
except Exception as ex:
    error_msg = "Critical error in Crypto Detector script: {}".format(str(ex))
    log_critical(logger, error_msg, exc_info=True)
    println("[-] {}".format(error_msg))
