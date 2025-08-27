import configparser

# For type checking
try:
    from ghidra.ghidra_builtins import *
except ImportError:
    pass

from ghidra.app.script import GhidraScriptUtil

import logging

# Suppress INFO messages from httpx
logging.getLogger('httpx').setLevel(logging.WARNING)

def read_config(section_name, key_name):
    """Read configuration from config file"""
    try:
        ghidra_script = GhidraScriptUtil()
        config_path = '{}/AskJOE/config.ini'.format(ghidra_script.USER_SCRIPTS_DIR)
        
        config = configparser.ConfigParser()
        
        # Check if file exists
        import os
        if not os.path.exists(config_path):
            return ""
        
        config.read(config_path)
        
        # Check if section and key exist
        if not config.has_section(section_name) or not config.has_option(section_name, key_name):
            return ""
        
        return str(config.get(section_name, key_name))
            
    except Exception as e:
        return ""

def ask_open_ai(prompt, decompiled_function=""):
    """Make OpenAI API call"""
    try:
        # Check if openai module is available
        try:
            from openai import OpenAI
        except ImportError as import_error:
            print("[-] OpenAI module not available: {}".format(import_error))
            return None
        
        # Get API key
        api_key = read_config('API_KEYS', 'openai_api_key')
        if not api_key or len(api_key) < 20:
            print("[-] Invalid or missing OpenAI API key")
            return None
            
        client = OpenAI(api_key=api_key)
        
        # Make API call
        full_prompt = "{}\n{}".format(prompt, decompiled_function)
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": full_prompt}],
            temperature=0.8,
            max_tokens=2048,
            top_p=1,
            frequency_penalty=0.2,
            presence_penalty=0
        )
        
        return response
        
    except Exception as e:
        print("[-] OpenAI API call failed: {}".format(e))
        return None




def parse_open_ai_response(response):
    """Parse OpenAI response"""
    try:
        if not response:
            return "No response received from OpenAI"
        
        # Check if it's a string (already parsed)
        if isinstance(response, str):
            return response
        
        # Check if it's a dict (JSON response)
        if isinstance(response, dict):
            if 'choices' in response and len(response['choices']) > 0:
                if 'message' in response['choices'][0] and 'content' in response['choices'][0]['message']:
                    return response['choices'][0]['message']['content']
                else:
                    return "Response format error: missing message content"
            else:
                return "Response format error: no choices found"
        
        # Check if it's an OpenAI response object
        if hasattr(response, 'choices') and len(response.choices) > 0:
            choice = response.choices[0]
            if hasattr(choice, 'message') and hasattr(choice.message, 'content'):
                return choice.message.content
            else:
                return "Response format error: choice missing message content"
        else:
            return "Response format error: missing choices attribute"
            
    except Exception as e:
        return "Error parsing response: {}".format(e)
