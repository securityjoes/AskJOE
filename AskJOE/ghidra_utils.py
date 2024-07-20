import re
import ghidra

# For type checking
try:
    from ghidra.ghidra_builtins import *
except ImportError:
    pass

from java.awt import Color
from ghidra.util.exception import CancelledException
from ghidra.app.plugin.core.colorizer import ColorizingService
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.data import StringDataType
from ghidra.program.model.mem import MemoryAccessException


def set_ghidra_plate_comment(address, comment):
    service = state().getTool().getService(ColorizingService)

    listing = currentProgram().getListing()
    code_unit = listing.getCodeUnitAt(address)
    code_unit.setComment(code_unit.PLATE_COMMENT, comment)
    service.setBackgroundColor(address, address, Color(143, 27, 104))


def rename_function(old_name, new_name):
    function_manager = currentProgram().getFunctionManager()
    core_func_obj = function_manager.getFunctionAt(old_name.getEntryPoint())
    core_func_obj.setName(new_name, ghidra.program.model.symbol.SourceType.DEFAULT)


def recover_stack_string(address):
    stack_string = ""
    current_instruction = currentProgram().getListing().getInstructionAt(address)
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


def print_joe_answer(option, open_ai_response=""):
    if open_ai_response:
        print(f"\n[+] AskJOE said: {option}\n{open_ai_response}\n")
    else:
        print(f"\n[+] AskJOE said: {option}\n")
