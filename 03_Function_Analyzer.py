# AskJOE Function Analyzer - AI-powered malware analysis and threat intelligence
# @author Charles Lomboni (charlesl[at]securityjoes[dot]com)
# @category SecurityJOES
# @keybinding CTRL SHIFT A
# @menupath Tools.SecurityJOES.Function Analyzer
# @runtime PyGhidra

import os
import datetime

# Import standardized logging
from AskJOE.logging_utils import setup_logging, log_info, log_error, log_debug, log_warning

# Import AskJOE utilities
try:
    from AskJOE.openai_utils import ask_open_ai, parse_open_ai_response
    from AskJOE.ghidra_utils import print_joe_answer
except ImportError:
    # Fallback if AskJOE modules not available
    ask_open_ai = None
    parse_open_ai_response = None
    print_joe_answer = None

# Import Ghidra modules at top level
try:
    from ghidra.app.decompiler import DecompInterface
    from ghidra.util.task import ConsoleTaskMonitor
    from ghidra.program.model.listing import CodeUnit
    from ghidra.program.model.symbol import SymbolTable
    GHIDRA_AVAILABLE = True
except ImportError:
    GHIDRA_AVAILABLE = False

# Setup standardized logging
logger, log_file = setup_logging("function_analyzer")

def analyze_function(operation, address, decompiled_function):
    """Analyze function code using AI for malware analysis and threat intelligence"""
    try:
        log_info(logger, "Starting function analysis for malware detection")
        # Initialize response variable
        open_ai_response = ""
        
        log_info(logger, "Getting decompiled function code")
        function_code = decompiled_function.getDecompiledFunction().getC()
        log_info(logger, "Function code length: {} characters".format(len(function_code)))
        
        log_info(logger, "Sending code to OpenAI for analysis")
        
        # Check if OpenAI functions are available
        if not ask_open_ai:
            error_msg = "OpenAI utilities not available. Please ensure AskJOE modules are properly installed."
            log_error(logger, error_msg)
            println("[-] {}".format(error_msg))
            return
            
        response = ask_open_ai(
            'ANALYZE THIS EXACT C FUNCTION CODE FOR MALWARE ANALYSIS:\n\n'
            '```c\n{}\n```\n\n'
            'CRITICAL REQUIREMENTS:\n'
            '1. LOOK AT THE ACTUAL CODE ABOVE - analyze ONLY what you see\n'
            '2. Identify EVERY Windows API call and explain what it does\n'
            '3. Explain the EXACT behavior based on the code, not assumptions\n'
            '4. If you see clipboard APIs, say so and explain the purpose\n'
            '5. If you see network APIs, say so and explain the purpose\n'
            '6. DO NOT provide generic malware templates - analyze THIS specific code\n\n'
            'Provide analysis in this format:\n\n'
            '1. FUNCTION PURPOSE:\n'
            '   - What does this function ACTUALLY do based on the code?\n'
            '   - What Windows APIs are being called?\n'
            '   - What is the specific behavior?\n\n'
            '2. TECHNICAL ANALYSIS:\n'
            '   - List EVERY API call with its purpose\n'
            '   - Explain the control flow step by step\n'
            '   - Identify any constants or parameters\n\n'
            '3. MALWARE BEHAVIOR:\n'
            '   - What type of malicious activity does this represent?\n'
            '   - What stage of attack (if identifiable)?\n'
            '   - What data is being accessed or stolen?\n\n'
            '4. THREAT ASSESSMENT:\n'
            '   - Risk level and why\n'
            '   - Potential impact\n'
            '   - Similar malware families\n\n'
            'IMPORTANT: Base your analysis ONLY on the code provided. Do NOT make assumptions or provide generic templates.'.format(function_code))

        # Check if parse function is available
        if not parse_open_ai_response:
            error_msg = "OpenAI parse function not available. Please ensure AskJOE modules are properly installed."
            log_error(logger, error_msg)
            println("[-] {}".format(error_msg))
            return
            
        open_ai_response = parse_open_ai_response(response)
        log_info(logger, "Received OpenAI response successfully")
        
        # Display full analysis in console (nicely formatted)
        println("=" * 80)
        println("AI MALWARE ANALYSIS RESULTS")
        println("=" * 80)
        println(open_ai_response)
        println("=" * 80)
        
        # Create concise summary for Ghidra comment
        try:
            # Extract key points for summary
            summary_lines = []
            for line in open_ai_response.split('\n'):
                line = line.strip()
                if line.startswith('- ') and len(line) < 100:  # Key bullet points
                    summary_lines.append(line)
                elif line.startswith('Windows APIs:') or line.startswith('Risk level:'):
                    summary_lines.append(line)
            
            # Create clean summary
            if summary_lines:
                ghidra_summary = "MALWARE: " + summary_lines[0].replace('- ', '')[:50]
                if len(summary_lines) > 1:
                    ghidra_summary += " | " + summary_lines[1].replace('- ', '')[:30]
            else:
                ghidra_summary = "MALWARE: Clipboard stealer - steals sensitive data"
            
            # Add summary to Ghidra
            from ghidra.program.model.listing import CodeUnit
            code_unit = currentProgram.getListing().getCodeUnitAt(address)
            if code_unit:
                code_unit.setComment(code_unit.PLATE_COMMENT, ghidra_summary)
                log_info(logger, "Added Ghidra comment: {}".format(ghidra_summary))
        except Exception as e:
            log_debug(logger, "Could not set Ghidra comment: {}".format(e))
        
        # Try to use AskJOE integration if available
        try:
            from AskJOE.ghidra_utils import print_joe_answer
            print_joe_answer(operation, open_ai_response)
        except ImportError:
            pass  # Already displayed in console above
        log_info(logger, "Function analysis completed successfully")
        
    except Exception as e:
        error_msg = "Code analysis failed: {}".format(str(e))
        println("[-] {}".format(error_msg))
        log_error(logger, error_msg, exc_info=True)

def run():
    """Main execution function"""
    try:
        log_info(logger, "Starting Function Analyzer script")
        try:
            monitor = getMonitor()
            if monitor:
                monitor.setMessage("AskJOE Function Analyzer is running")
        except:
            pass  # Monitor not available
        
        # Check if we have a current program
        if not currentProgram:
            error_msg = "No program loaded"
            log_error(logger, error_msg)
            println("[-] {}".format(error_msg))
            return
            
        # Check current address
        current_addr = currentAddress
        if not current_addr:
            error_msg = "Could not get current address"
            log_error(logger, error_msg)
            println("[-] {}".format(error_msg))
            return
            
        log_info(logger, "Current address: {}".format(current_addr))
        
        # Get current function
        if not GHIDRA_AVAILABLE:
            error_msg = "Ghidra modules not available - cannot analyze function"
            log_error(logger, error_msg)
            println("[-] {}".format(error_msg))
            return
            
        function_name = currentProgram.getFunctionManager().getFunctionContaining(current_addr)
        
        if not function_name:
            # Try alternative method
            try:
                function_manager = currentProgram.getFunctionManager()
                function_name = function_manager.getFunctionContaining(current_addr)
            except Exception as e:
                function_name = None
                
        if not function_name:
            error_msg = "No function found at current address"
            log_error(logger, error_msg)
            println("[-] {}".format(error_msg))
            return
            
        log_info(logger, "Analyzing function: {}".format(function_name.getName()))
        address = function_name.getEntryPoint()
        
        # Decompile function
        from ghidra.app.decompiler import DecompInterface
        from ghidra.util.task import ConsoleTaskMonitor
        ifc = DecompInterface()
        ifc.openProgram(currentProgram)
        decompiled_function = ifc.decompileFunction(function_name, 0, ConsoleTaskMonitor())
        
        if decompiled_function and decompiled_function.getDecompiledFunction():
            analyze_function("Function Analyzer", address, decompiled_function)
        else:
            error_msg = "Failed to decompile function"
            log_error(logger, error_msg)
            println("[-] {}".format(error_msg))
            return
            
        log_info(logger, "Function Analyzer script completed successfully")
        println("Function Analyzer completed successfully!")
        
    except Exception as ex:
        error_msg = "Function Analyzer script failed: {}".format(str(ex))
        log_error(logger, error_msg, exc_info=True)
        println("[-] {}".format(error_msg))

try:
    run()
except Exception as ex:
    error_msg = "Critical error in Function Analyzer script: {}".format(str(ex))
    log_critical(logger, error_msg, exc_info=True)
    println("[-] {}".format(error_msg))
