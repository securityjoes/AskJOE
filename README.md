# AskJOE

## What is AskJOE?
AskJoe is a tool that utilizes [OpenAI](https://openai.com/) to assist researchers wanting to use [Ghidra](https://github.com/NationalSecurityAgency/ghidra) as their malware analysis tool. It was based on the [Gepetto](https://github.com/JusticeRage/Gepetto) idea.
With its capabilities, OpenAI highly simplifies the practice of reverse engineering, allowing researchers to better detect and mitigate threats. 

![AskJOE Running](/imgs/AskJOE-Running.gif "AskJOE Running")

The tool is free to use, under the limitations of Github.

Author: https://twitter.com/charleslomboni | Threat Researcher, Security Joes

## Updates - 05/23/2023
- askChoices added
- Explain selection added
- Confg file added

## Updates - 05/11/2023
- Execute all added
- Stack String added
- Rename function added
- Changed color from function renamed added
- Changed max_tokens

## Updates - 05/08/2023
- Code refactored
- Explain function added
- Simplify code added
- Set OpenAI answer to comment added
- Monitor messages added

## Dependencies
- Requests: `pip install requests`
- [Ghidra](https://github.com/NationalSecurityAgency/ghidra)
- [Pyhidra](https://github.com/dod-cyber-crime-center/pyhidra)
- [Python3](https://www.python.org/downloads/)


## Limitations
> OpenAI has a hard limit of 4096 tokens for each API call, so if your text is longer than that, you'll need to split it up. However, OpenAI currently does not support stateful conversations over multiple API calls, which means it does not remember the previous API call.


## How to install?
- Copy the AskJOE files to the ghidra_scripts folder

![ghidra_scripts](/imgs/ghidra_scripts_folder.png "ghidra_scripts")