# AskJOE what this function does or ask to simplify the code to
# python and JOE will help you understand it. Just click anywhere
# within the function you would like to understand and AskJOE!
# @author Charles Lomboni (charlesl@securityjoes.com)
# @category SecurityJoes
# @keybinding CTRL SHIFT K
# @menupath Tools.AskJOE
# @toolbar JOES.png

import json
import re

import ghidra
import requests

# For type checking
try:
    from ghidra.ghidra_builtins import *
except:
    pass

from java.awt import Color
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.util.exception import CancelledException
from ghidra.app.plugin.core.colorizer import ColorizingService

OPENAI_API_KEY = ""
service = state.getTool().getService(ColorizingService)


def ask_open_ai(prompt, decompiled_function=""):
    monitor.setMessage("JOE is thinking")
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {OPENAI_API_KEY}',
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
    codeUnit = listing.getCodeUnitAt(address)
    codeUnit.setComment(codeUnit.PLATE_COMMENT, comment)
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
    monitor.setMessage("AskJOE is detecting Stack Strings")
    print_joe_answer(op_stack_strings)

    programList = currentProgram.getListing()
    instruction = programList.getInstructions(1)
    while instruction.hasNext() and not monitor.isCancelled():
        inst = instruction.next()
        instStr = str(inst.getScalar(1)).replace("0x", "")
        if not instStr == "None" and (len(instStr) % 2) == 0 and not "-" in instStr:
            stackStr, maxAddr = recover_stack_string(inst.address)
            FilteredStackStr: str = re.sub(
                r'[^a-zA-Z0-9 .,\-*/\[\]{}!@#$%^&()=~:"\'\\+?><`_;]+', '', stackStr)
            if len(FilteredStackStr) > 1 and FilteredStackStr == stackStr:
                print(f"[+] {str(inst.address)} {stackStr}")
                codeUnit = programList.getCodeUnitAt(inst.address)
                codeUnit.setComment(codeUnit.PRE_COMMENT, stackStr)

            while str(inst.address) != maxAddr:
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


def explain_function(address, function_name, decompiled_function, op_explain_code):
    response = ask_open_ai(
        'Can you explain what the following function does and suggest a better name for it?',
        decompiled_function.getDecompiledFunction().getC()
    )

    open_ai_response = parse_open_ai_response(response)
    set_ghidra_plate_comment(address, open_ai_response)
    new_function_name = re.search("\"([\S]+)\"|\'([\S]+)\'", open_ai_response).group()
    print_joe_answer(op_explain_code, open_ai_response)
    rename_function(function_name, new_function_name.replace('"', '').replace('(', '').replace(')', ''))


def ask_joe(function_name, decompiled_function):
    address = function_name.getEntryPoint()

    op_execute_all = "Execute all."
    op_explain_code = "Explain function."
    op_simplify_code = "Simplify code."
    op_stack_string = "Stack Strings."

    op = askInt("AskJOE - What should JOE do for you?",
                f"(0) {op_execute_all} "
                f"(1) {op_explain_code} "
                f"(2) {op_simplify_code} "
                f"(3) {op_stack_string}")

    if op == 0:
        explain_function(address, function_name, decompiled_function, op_explain_code)
        simplify_code(decompiled_function, op_simplify_code)
        detect_stack_strings(op_stack_string)

    if op == 1:
        explain_function(address, function_name, decompiled_function, op_explain_code)

    if op == 2:
        simplify_code(decompiled_function, op_simplify_code)

    if op == 3:
        detect_stack_strings(op_stack_string)


def run():
    monitor.setMessage("AskJOE is running")
    if "" == OPENAI_API_KEY:
        print("\n[-] You have to fill in the OPENAI API key first!\n")
        return

    current_program = getCurrentProgram()
    ifc = DecompInterface()
    ifc.openProgram(current_program)

    function_name = getFunctionContaining(currentAddress)
    decompiled_function = ifc.decompileFunction(function_name, 0, ConsoleTaskMonitor())
    ask_joe(function_name, decompiled_function)


try:
    run()
except CancelledException as gEx:
    print(f'[-] {gEx.getMessage()}')
except Exception as ex:
    print(f'[-] {ex}')
