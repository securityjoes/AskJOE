# AskJOE what this function does or ask to simplify the code to
# python and JOE will help you understand it. Just click anywhere
# within the function you would like to understand and AskJOE!
# @author Charles Lomboni (charlesl@securityjoes.com)
# @category SecurityJoes
# @keybinding CTRL SHIFT K
# @menupath Tools.AskJOE
# @toolbar JOES.png


from AskJOE.constants import Operation
from AskJOE.ghidra_utils import *
from AskJOE.openai_utils import *
from AskJOE.data import *
from AskJOE import utils

from java.lang import String
from java.util import ArrayList

from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.script import GhidraScriptUtil
from ghidra.program.model.symbol import SourceType

import os
import requests
import AskJOE.capa_explorer

# For type checking
try:
    from ghidra.ghidra_builtins import *
except ImportError:
    pass

monitor = ConsoleTaskMonitor()


def detect_crypto_constants(operation):
    print_joe_answer(operation)
    symbolTable = currentProgram().getSymbolTable()
    for const in non_sparse_consts:
        const["byte_array"] = utils.pack_constant(const)
        found = currentProgram().getMemory().findBytes(
            currentProgram().getMinAddress(), const["byte_array"], None, True, monitor
        )
        if found:
            labelName = "aj_crypto_constant_" + const["algorithm"] + "_" + const["name"]
            print(f"[+] {const['algorithm']} {const['name']} 0x{found} -> {labelName}")
            symbolTable.createLabel(found, labelName, SourceType.USER_DEFINED)

    listing = currentProgram().getListing()
    instruction = listing.getInstructions(1)
    while instruction.hasNext():
        inst = instruction.next()
        for const in sparse_consts:
            if str(const["array"][0]).upper() == str(inst.getScalar(1)).upper():
                labeladdr = inst.getAddress()
                for val in const["array"][1:]:
                    inst = instruction.next()
                    if not str(val).upper() == str(inst.getScalar(1)).upper():
                        if const["name"] == "SHA1_H" and const["array"][-1]:
                            labelName = "aj_crypto_constant_MD5_initstate"
                            print(f"[+] MD5_initstate 0x{labeladdr} -> {labelName}")
                            symbolTable.createLabel(labeladdr, labelName, SourceType.USER_DEFINED)
                        break
                else:
                    labelName = "aj_crypto_constant_" + const["algorithm"] + "_" + const["name"]
                    print(f"[+] {const['name']} 0x{labeladdr} -> {labelName}")
                    symbolTable.createLabel(labeladdr, labelName, SourceType.USER_DEFINED)


def ai_triage(operation):
    strings = []
    dataIterator = currentProgram().getListing().getDefinedData(True)

    while dataIterator.hasNext() and not monitor.isCancelled():
        data = dataIterator.next()
        dataType = data.getDataType()

        if isinstance(dataType, StringDataType):
            try:
                string_value = data.getDefaultValueRepresentation()
                strings.append(string_value)
            except MemoryAccessException as e:
                println(f"Memory access error at {data.getAddress()}: {e}")

    symbolTable = currentProgram().getSymbolTable()

    imports = set()
    externalSymbols = symbolTable.getExternalSymbols()
    for symbol in externalSymbols:
        if not symbol.getName().startswith("_"):
            imports.add(symbol.getName())

    str_openAI = strings if len(strings) > 4 else []

    response = ask_open_ai(
        f'Based on these imports {imports} and strings {str_openAI}, can you help me '
        f'understand what is the goal of this file? Also, is it malicious or not? Can you '
        f'also correlate it and tell me some intelligence context about it? '
        f'Please, give me a summary of this without recommendations.'
    )

    open_ai_response = parse_open_ai_response(response)
    print_joe_answer(operation, open_ai_response)


def capa_analysis(operation):
    print_joe_answer(operation)

    capa_url = read_config('CAPA', 'GITHUB')
    response = requests.get(capa_url)
    script_content = response.text

    ghidra_script = GhidraScriptUtil()

    # Step 3: Save the script into the directory
    script_path = os.path.join(f"{ghidra_script.USER_SCRIPTS_DIR}/AskJOE", "capa_explorer.py")

    if not os.path.exists(script_path):
        with open(script_path, "w") as script_file:
            script_file.write(script_content)

    AskJOE.capa_explorer.main()


def detect_stack_strings(option):
    print_joe_answer(option)
    program_list = currentProgram().getListing()
    instructions = program_list.getInstructions(1)

    while instructions.hasNext() and not monitor.isCancelled():
        inst = instructions.next()
        inst_str = str(inst.getScalar(1)).replace("0x", "")

        if inst_str != "None" and len(inst_str) % 2 == 0 and "-" not in inst_str:
            stack_str, max_addr = recover_stack_string(inst.getAddress())
            filtered_stack_str = re.sub(r'[^a-zA-Z0-9 .,\-*/\[\]{}!@#$%^&()=~:"\'\\+?><`_;]+', '', stack_str)

            if len(filtered_stack_str) > 2 and filtered_stack_str == stack_str:
                print(f"[+] {str(inst.getAddress())} {stack_str}")
                code_unit = program_list.getCodeUnitAt(inst.getAddress())
                code_unit.setComment(code_unit.PRE_COMMENT, stack_str)

            while str(inst.getAddress()) != max_addr:
                if not instructions.hasNext():
                    break
                inst = instructions.next()


def simplify_code(operation, decompiled_function):
    response = ask_open_ai(
        'Take this C code, suggest a better name for this function and create a Python code '
        'to reflect this C code. If something is missing please complete it. '
        'Please, only show the Python code without any additional explanation.',
        decompiled_function.getDecompiledFunction().getC()
    )

    open_ai_response = parse_open_ai_response(response)
    print_joe_answer(operation, open_ai_response)


def explain_opcodes(operation):
    listing = currentProgram().getListing()
    selection = currentSelection()

    opcodes = []

    if selection:
        for addressRange in selection:
            start_address = addressRange.getMinAddress()
            end_address = addressRange.getMaxAddress().next()  # This gives the address right after the end address

            instructions = listing.getInstructions(start_address, True)

            for instruction in instructions:
                inst_addr = instruction.getAddress()

                if inst_addr >= end_address:
                    break

                opcode = instruction.getBytes()

                # Ensure all bytes are within the valid range
                valid_opcode = [byte & 0xFF for byte in opcode]
                opcodes.append(' '.join(f'{byte:02X}' for byte in valid_opcode))

    opcodes_str = ' '.join(opcodes)

    response = ask_open_ai(
        'I would like to understand what these opcodes does. '
        'Can you explain what malware author can do with it? Please, pay attention '
        'that if the opcodes are related to some windows internals part I appreciate '
        'your explanation. As a beginner, just give me the idea behind the opcodes '
        'without convert it and suggest a name for this part of code.',
        ''.join(opcodes_str)
    )

    open_ai_response = parse_open_ai_response(response)
    print_joe_answer(operation, open_ai_response)


def explain_function(operation, address, decompiled_function):
    response = ask_open_ai(
        'Can you explain what the following function does to a beginner '
        'who wants to start in malware analysis and reverse engineering?',
        decompiled_function.getDecompiledFunction().getC()
    )

    open_ai_response = parse_open_ai_response(response)
    set_ghidra_plate_comment(address, open_ai_response)
    print_joe_answer(operation, open_ai_response)


def better_name(option, function_name, decompiled_function):
    print_joe_answer(option)
    response = ask_open_ai(
        'Can you suggest a better name for it? I want your answer to be just a better name, '
        'in a clear text without code format like "```".',
        decompiled_function.getDecompiledFunction().getC()
    )

    open_ai_response = parse_open_ai_response(response)
    print(f'A better name to this function is: {open_ai_response}')
    rename_function(function_name, open_ai_response)


def search_xor(option):
    print_joe_answer(option)
    instructions = currentProgram().getListing().getInstructions(True)

    for instruction in instructions:
        if instruction.getMnemonicString() == "XOR":
            numOperands = instruction.getNumOperands()

            if numOperands == 2:
                operand1 = instruction.getOpObjects(0)[0]
                operand2 = instruction.getOpObjects(1)[0]

                if operand1 != operand2:
                    if isinstance(operand2, ghidra.program.model.scalar.Scalar):
                        print(f"[+] Address: {instruction.getAddress()} - {instruction}")
                    else:
                        print(f"[+] Address: {instruction.getAddress()} - {instruction}")


def ask_user_prompt(operation):
    user_prompt = askString("User Prompt", "What would you like to Ask?")

    response = ask_open_ai(user_prompt)

    open_ai_response = parse_open_ai_response(response)
    print_joe_answer(f"{operation} {user_prompt}", open_ai_response)


def ask_joe(function_name, ifc):
    address = function_name.getEntryPoint()

    choices = askChoices(
        String("AskJOE"),
        String("What should JOE do for you?"),
        ArrayList([0, 1, 2, 3, 4, 5, 6, 7, 8, 9]),
        ArrayList([
            "User Prompt",
            "AI Triage",
            "Explain function",
            "Explain selection",
            "Better Name",
            "Simplify code",
            "Stack Strings",
            "Search XORs",
            "Crypto Consts",
            "Capa Analysis"
        ])
    )

    decompiled_function = ifc.decompileFunction(function_name, 0, ConsoleTaskMonitor())

    if 0 in choices:
        monitor.setMessage(f"AskJOE is asking {Operation.PROMPT.value}")
        ask_user_prompt(Operation.PROMPT.value)

    if 1 in choices:
        monitor.setMessage(f"AskJOE is running {Operation.AI_TRIAGE.value}")
        ai_triage(Operation.AI_TRIAGE.value)

    if 2 in choices:
        monitor.setMessage(f"AskJOE is {Operation.EXPLAIN_FUNCTION.value}")
        explain_function(Operation.EXPLAIN_FUNCTION.value, address, decompiled_function)

    if 3 in choices and 2 not in choices and currentSelection() is not None:
        monitor.setMessage(f"AskJOE is {Operation.EXPLAIN_SELECTION.value}")
        explain_opcodes(Operation.EXPLAIN_SELECTION.value)

    if 4 in choices:
        monitor.setMessage(f"AskJOE is detecting {Operation.BETTER_NAME.value}")
        better_name(Operation.BETTER_NAME.value, function_name, decompiled_function)

    if 5 in choices:
        monitor.setMessage(f"AskJOE is {Operation.SIMPLIFY_CODE.value}")
        simplify_code(Operation.SIMPLIFY_CODE.value, decompiled_function)

    if 6 in choices:
        monitor.setMessage(f"AskJOE is detecting {Operation.STACK_STRINGS.value}")
        detect_stack_strings(Operation.STACK_STRINGS.value)

    if 7 in choices:
        monitor.setMessage(f"AskJOE is detecting {Operation.XORS.value}")
        search_xor(Operation.XORS.value)

    if 8 in choices:
        monitor.setMessage(f"AskJOE is {Operation.CRYPTO_CONSTS.value}")
        detect_crypto_constants(Operation.CRYPTO_CONSTS.value)

    if 9 in choices:
        monitor.setMessage(f"AskJOE is running {Operation.CAPA_ANALYSIS.value}")
        capa_analysis(Operation.CAPA_ANALYSIS.value)


def run():
    monitor.setMessage("AskJOE is running")

    ifc = DecompInterface()
    ifc.openProgram(currentProgram())
    function_name = getFunctionContaining(currentAddress())
    ask_joe(function_name, ifc)


try:
    try:
        open(dbPath).read()
    except:
        dbPath = askFile("db.json path", "Choose file:")
        dbPath = str(dbPath)
        db = open(dbPath.replace("db.json", "data.py"), "a")
        db.write("\n\n")
        db.write("dbPath = r'" + dbPath + "'")
        db.close()
    run()
except Exception as ex:
    print(f'[-] {ex}')
