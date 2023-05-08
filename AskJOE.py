# AskJOE what this function does or ask to simplify the code to
# python and JOE will help you understand it. Just click anywhere
# within the function you would like to understand and AskJOE!
# @author Charles Lomboni (charlesl@securityjoes.com)
# @category SecurityJoes
# @keybinding CTRL SHIFT K
# @menupath Tools.AskJOE
# @toolbar JOES.png

import requests
import json

# For type checking
try:
    from ghidra.ghidra_builtins import *
except:
    pass

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.util.exception import CancelledException

OPENAI_API_KEY = ""


def ask_open_ai(prompt, decompiled_function):
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
            "prompt": f"{prompt}\n\n {decompiled_function}",
            "temperature": 0.7,
            "max_tokens": 2200,
            "top_p": 1,
            "frequency_penalty": 0.2,
            "presence_penalty": 0
        }
    )
    return response


def parse_open_ai_response(response):
    monitor.setMessage("Parsing OpenAI response")
    json_loaded = json.loads(response.text)
    return json_loaded['choices'][0]['text']


def print_joe_answer(option, open_ai_response):
    print(f"\n[+] AskJOE said: {option}\n{open_ai_response}\n")


def set_ghidra_comment(comment):
    address = parseAddress(str(getFunctionContaining(currentAddress)).split('_')[1])
    listing = currentProgram.getListing()
    codeUnit = listing.getCodeUnitAt(address)
    codeUnit.setComment(codeUnit.PLATE_COMMENT, comment)


def ask_joe(decompiled_function):
    explain_code = "Explain function."
    simplify_code = "Simplify code."
    op = askInt("AskJOE - Type the number", f"(1) {explain_code} (2) {simplify_code}")

    if op == 1:
        # ------------------------------------------------------------------------------------
        response = ask_open_ai(
            'Can you explain what the following C function does and suggest a better name for it?',
            decompiled_function.getDecompiledFunction().getC()
        )

        open_ai_response = parse_open_ai_response(response)
        set_ghidra_comment(open_ai_response)
        print_joe_answer(explain_code, open_ai_response)

    if op == 2:
        # ------------------------------------------------------------------------------------
        response = ask_open_ai(
            'Take this C code, suggest a better name for this function and create a Python code '
            'to reflect this C code, please add all necessary imports. '
            'Please, only show the Python code without any additional explanation.',
            decompiled_function.getDecompiledFunction().getC()
        )

        open_ai_response = parse_open_ai_response(response)
        print_joe_answer(simplify_code, open_ai_response)


def run():
    monitor.setMessage("AskJOE is running")
    if "" == OPENAI_API_KEY:
        print("\n[-] You have to fill in the OPENAI API key first!\n")
        return

    current_program = getCurrentProgram()
    ifc = DecompInterface()
    ifc.openProgram(current_program)

    function_name = getFunctionContaining(currentAddress)

    # decompile the function and print the pseudo C
    decompiled_function = ifc.decompileFunction(function_name, 0, ConsoleTaskMonitor())

    ask_joe(decompiled_function)


try:
    run()
except CancelledException as gEx:
    print(f'[-] {gEx.getMessage()}')
except Exception as ex:
    print(f'[-] {ex}')
