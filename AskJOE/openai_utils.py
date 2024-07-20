import configparser

# For type checking
try:
    from ghidra.ghidra_builtins import *
except ImportError:
    pass

from openai import OpenAI
from ghidra.app.script import GhidraScriptUtil

import logging

# Suppress INFO messages from httpx
logging.getLogger('httpx').setLevel(logging.WARNING)

def read_config(section_name, key_name) -> str:
    ghidra_script = GhidraScriptUtil()
    config = configparser.ConfigParser()
    config.read(f'{ghidra_script.USER_SCRIPTS_DIR}/AskJOE/config.ini')
    return str(config.get(section_name, key_name))


def ask_open_ai(prompt, decompiled_function="") -> object:
    client = OpenAI(api_key=read_config('KEY', 'OPEN_AI'))

    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": f"{prompt}\n{decompiled_function}"}],
        temperature=0.8,
        max_tokens=2048,
        top_p=1,
        frequency_penalty=0.2,
        presence_penalty=0
    )

    return response


def parse_open_ai_response(response):
    try:
        return response.choices[0].message.content
    except AttributeError:
        raise Exception(response.choices[0].message.content)
