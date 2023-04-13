# AskJOE what this function does, and JOE will help you understand it.
# Just click anywhere within the function you would like to understand and AskJOE!
# @author Charles Lomboni (charlesl@securityjoes.com)
# @category SecurityJoes

import requests
import json

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

OPENAI_API_KEY = ""

def main():

  if "" == OPENAI_API_KEY:
    print("\nYou have to fill in the OPENAI API key first!\n")
    return

  program = getCurrentProgram()
  ifc = DecompInterface()
  ifc.openProgram(program)

  functionName = getFunctionContaining(currentAddress)

  # decompile the function and print the pseudo C
  results = ifc.decompileFunction(functionName, 0, ConsoleTaskMonitor())

  headers = {
      'Content-Type': 'application/json',
      'Authorization': f'Bearer {OPENAI_API_KEY}',
  }

  # What this function does?
  response = requests.post(
    'https://api.openai.com/v1/completions', 
    headers=headers, 
    json={
      "model":"text-davinci-003",
      "prompt":"What does this function?\n\n "+ results.getDecompiledFunction().getC() +" ",
      "temperature":0.7,
      "max_tokens":1500,
      "top_p":1,
      "frequency_penalty":0.2,
      "presence_penalty":0
    }
  )

  json_loaded = json.loads(response.text)
  print(f"\nAskJOE said: \n{json_loaded['choices'][0]['text']}\n")

try:
    main()
except:
    print("Oops... something went wrong .. :/")
