# AskJOE what this function does or ask to simplify the code to
# python and JOE will help you understand it. Just click anywhere
# within the function you would like to understand and AskJOE!
# @author Charles Lomboni (charlesl@securityjoes.com)
# @category SecurityJoes
# @keybinding CTRL SHIFT K
# @menupath Tools.AskJOE
# @toolbar JOES.png


import ghidra
import requests
import configparser
import json
import re

# For type checking
try:
    from ghidra.ghidra_builtins import *
except:
    pass

from jpype import java
from java.awt import Color
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.util.exception import CancelledException
from ghidra.app.plugin.core.colorizer import ColorizingService
# For USER_SCRIPTS_DIR
from ghidra.app.script.GhidraScriptUtil import *

service = state.getTool().getService(ColorizingService)


def read_api_key():
    config = configparser.ConfigParser()
    config.read(f'{USER_SCRIPTS_DIR}/config.ini')
    return str(config.get('KEY', 'OPEN_AI'))


def ask_open_ai(prompt, decompiled_function=""):
    monitor.setMessage("JOE is thinking")
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {read_api_key()}',
    }
    response = requests.post(
        'https://api.openai.com/v1/completions',
        headers=headers,
        json={
            "model": "text-davinci-003",
            "prompt": f"{prompt}\n{decompiled_function}",
            "temperature": 0.8,
            "max_tokens": 2048,
            "top_p": 1,
            "frequency_penalty": 0.2,
            "presence_penalty": 0
        }
    )
    return response


def parse_open_ai_response(response):
    monitor.setMessage("Parsing OpenAI response")
    json_loaded = json.loads(response.text)

    try:
        return json_loaded['choices'][0]['text']
    except:
        raise Exception(json_loaded['error']['message'])


def print_joe_answer(option, open_ai_response=""):
    if open_ai_response != "":
        print(f"\n[+] AskJOE said: {option}\n{open_ai_response}\n")
    else:
        print(f"\n[+] AskJOE said: {option}\n")


def set_ghidra_plate_comment(address, comment):
    listing = currentProgram.getListing()
    code_unit = listing.getCodeUnitAt(address)
    code_unit.setComment(code_unit.PLATE_COMMENT, comment)
    service.setBackgroundColor(address, address, Color(143, 27, 104))


def rename_function(old_name, new_name):
    function_manager = currentProgram.getFunctionManager()
    core_func_obj = function_manager.getFunctionAt(old_name.getEntryPoint())
    core_func_obj.setName(new_name, ghidra.program.model.symbol.SourceType.DEFAULT)


def recover_stack_string(address):
    """
    https://github.com/reb311ion/replica/blob/fede41b9afd2ef5e33c860ce114e8a24193751ac/replica.py#L214
    :param address:
    :return:
    """
    stack_string = ""
    current_instruction = getInstructionAt(address)
    current_address = address

    while current_instruction and current_instruction.getScalar(1):

        decimal_value = current_instruction.getScalar(1).value
        try:
            if decimal_value == 0 and stack_string != "" \
                    and current_instruction.getNext().getScalar(1).value == 0:
                return stack_string, str(current_address)
        except:
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
                except:

                    decimal_value = 0
                    pass

            else:
                stack_string_part += chr(decimal_value & 0xff)
                decimal_value = decimal_value >> 8

        stack_string += stack_string_part
        try:
            if (current_instruction.getNext().getScalar(1) is None) \
                    and (current_instruction.getNext().getNext().getScalar(1) is not None):
                current_instruction = current_instruction.getNext()

        except:
            pass

        current_instruction = current_instruction.getNext()
        current_address = current_instruction.address

    return stack_string, str(current_address)


def detect_stack_strings(op_stack_strings):
    """
    https://github.com/reb311ion/replica/blob/fede41b9afd2ef5e33c860ce114e8a24193751ac/replica.py#L560
    :return:
    """
    monitor.setMessage(f"AskJOE is detecting {op_stack_strings}")
    print_joe_answer(op_stack_strings)

    program_list = currentProgram.getListing()
    instruction = program_list.getInstructions(1)
    while instruction.hasNext() and not monitor.isCancelled():
        inst = instruction.next()
        inst_str = str(inst.getScalar(1)).replace("0x", "")
        if not inst_str == "None" and (len(inst_str) % 2) == 0 and not "-" in inst_str:
            stack_str, max_addr = recover_stack_string(inst.address)
            filtered_stack_str: str = re.sub(
                r'[^a-zA-Z0-9 .,\-*/\[\]{}!@#$%^&()=~:"\'\\+?><`_;]+', '', stack_str)
            if len(filtered_stack_str) > 2 and filtered_stack_str == stack_str:
                print(f"[+] {str(inst.address)} {stack_str}")
                code_unit = program_list.getCodeUnitAt(inst.address)
                code_unit.setComment(code_unit.PRE_COMMENT, stack_str)

            while str(inst.address) != max_addr:
                inst = instruction.next()


def simplify_code(decompiled_function, op_simplify_code):
    response = ask_open_ai(
        'Take this C code, suggest a better name for this function and create a Python code '
        'to reflect this C code. If something is missing please complete it. '
        'Please, only show the Python code without any additional explanation.',
        decompiled_function.getDecompiledFunction().getC()
    )

    open_ai_response = parse_open_ai_response(response)
    print_joe_answer(op_simplify_code, open_ai_response)


def explain_opcodes(op_explain_opcodes):
    # Get the current program
    current_program = state.getCurrentProgram()

    # Get the listing of the program
    listing = current_program.getListing()

    # Get the current selection in the listing
    selection = currentSelection

    opcodes = []

    # Iterate over the selection
    for addressRange in selection:
        # Get the address range
        start_address = addressRange.getMinAddress()
        end_address = parseAddress(hex(int(str(addressRange.getMaxAddress()), 16) + 1))

        # Get the instructions in the address range
        instructions = listing.getInstructions(start_address, True)

        # Iterate over the instructions
        for instruction in instructions:
            inst_addr = instruction.getAddress()

            if inst_addr == end_address:
                break

            # Get the opcode (machine code)
            opcode = instruction.getBytes()
            opcodes.append(bytearray(opcode).hex())

    response = ask_open_ai(
        'I would like to understand what these opcodes does. '
        'Can you explain what malware author can do with it? Please, pay attention '
        'that if the opcodes are related to some windows internals part I appreciate '
        'your explanation. As a beginner, just give me the idea behind the opcodes '
        'without convert it and suggest a name for this part of code.',
        ''.join(opcodes)
    )

    open_ai_response = parse_open_ai_response(response)
    print_joe_answer(op_explain_opcodes, open_ai_response)


def explain_function(address, function_name, decompiled_function, op_explain_code):
    response = ask_open_ai(
        'Can you explain what the following function does and suggest a better name for it?',
        decompiled_function.getDecompiledFunction().getC()
    )

    open_ai_response = parse_open_ai_response(response)
    set_ghidra_plate_comment(address, open_ai_response)
    new_function_name = re.search("\"([^\@\[][\S]+)\"|\'([^\@\[][\S]+)\'|ould be ([^\@\[][\s]+)",
                                  open_ai_response).group()
    print_joe_answer(op_explain_code, open_ai_response)
    rename_function(function_name,
                    new_function_name.replace('"', '').replace('(', '').replace(')', '').replace('.', ''))


def search_xor(op_xor):
    monitor.setMessage(f"AskJOE is detecting {op_xor}")
    print_joe_answer(op_xor)

    # Get all instruction from the binary
    instructions = currentProgram.getListing().getInstructions(True)

    for ins in instructions:
        mnemonic = ins.getMnemonicString()
        if "XOR" == mnemonic:
            operand1 = ins.getOpObjects(0)
            operand2 = ins.getOpObjects(1)

            # Search for registers
            if len(operand1) == 1 and len(operand2) == 1:
                if (isinstance(operand1[0], ghidra.program.model.lang.Register) or
                        isinstance(operand2[0], ghidra.program.model.lang.Register)):
                    reg1 = operand1[0].getName()
                    reg2 = operand2[0].getName()

                    # XOR EAX, EAX is not interesting for us.
                    # The goal here is search for different registers
                    if reg1 != reg2:
                        print(f"[+] Address: {ins.address} - {ins}\n")

            # Search for hex constants
            if '0x' in str(operand1) or '0x' in str(operand2):
                print(f"[+] Address: {ins.address} - {ins}\n")


def ask_user_prompt(op_prompt):
    user_prompt = askString("User Prompt", "What would you like to Ask?")

    response = ask_open_ai(user_prompt)

    open_ai_response = parse_open_ai_response(response)
    print_joe_answer(f"{op_prompt} {user_prompt}", open_ai_response)


def ask_joe(function_name, ifc):
    address = function_name.getEntryPoint()

    choices = askChoices(
        "AskJOE", "What should JOE do for you?",
        java.util.ArrayList([0, 1, 2, 3, 4, 5]),
        java.util.ArrayList(["Explain function", "Explain selection", "Simplify code", "Stack Strings",
                             "Search XORs", "User Prompt"])
    )

    op_explain_code = "Explain Function."
    op_explain_selection = "Explain Selection."
    op_simplify_code = "Simplify Code."
    op_stack_string = "Stack Strings."
    op_xor = "Search XORs."
    op_prompt = "User Prompt."

    decompiled_function = ifc.decompileFunction(function_name, 0, ConsoleTaskMonitor())

    if 0 in choices:
        explain_function(address, function_name, decompiled_function, op_explain_code)

    if 1 in choices and 0 not in choices:
        explain_opcodes(op_explain_selection)

    if 2 in choices:
        simplify_code(decompiled_function, op_simplify_code)

    if 3 in choices:
        detect_stack_strings(op_stack_string)

    if 4 in choices:
        search_xor(op_xor)

    if 5 in choices:
        ask_user_prompt(op_prompt)


def run():
    monitor.setMessage("AskJOE is running")

    if "" == read_api_key() or read_api_key() is None:
        print("\n[-] You have to fill in the OPENAI API key first!\n")
        return

    current_program = getCurrentProgram()
    ifc = DecompInterface()
    ifc.openProgram(current_program)

    function_name = getFunctionContaining(currentAddress)
    ask_joe(function_name, ifc)


try:
    run()
except CancelledException as gEx:
    print(f'[-] {gEx.getMessage()}')
except Exception as ex:
    print(f'[-] {ex}')