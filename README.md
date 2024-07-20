# AskJOE

## What is AskJOE?
AskJoe is a tool that utilizes [OpenAI](https://openai.com/) to assist researchers wanting to use [Ghidra](https://github.com/NationalSecurityAgency/ghidra) as their malware analysis tool. It was based on the [Gepetto](https://github.com/JusticeRage/Gepetto) idea.
With its capabilities, OpenAI highly simplifies the practice of reverse engineering, allowing researchers to better detect and mitigate threats. 

![AskJOE Running](/imgs/AskJOE-updated-running.gif "AskJOE Running")

The tool is free to use, under the limitations of Github.

Author: https://twitter.com/moval0x1 | Threat Researcher, Security Joes

## Updates - 07/20/2024
- Ghidrathon added and removed pyhidra
- Refactored Code
- AI Triage added
- Better Name added
- Search for crypto constants added
- Mandiant CAPA added

## Updates - 07/31/2023
- Search XORs
- Ask User Prompt (To OpenAI)

## Updates - 05/23/2023
- askChoices added
- Explain selection added
- Config file added

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
- requests: `pip install requests`
- flare-capa: `pip install flare-capa`
- openai: `pip install openai`
- [Ghidra](https://github.com/NationalSecurityAgency/ghidra)
- [Python3](https://www.python.org/downloads/)
- [Ghidrathon](https://github.com/mandiant/Ghidrathon)


## Limitations
> OpenAI has a hard limit of 4096 tokens for each API call, so if your text is longer than that, you'll need to split it up. However, OpenAI currently does not support stateful conversations over multiple API calls, which means it does not remember the previous API call.

> By now, It only supports Linux OS.

## How to install?
- Copy the AskJOE files to the ghidra_scripts folder

![ghidra_scripts](/imgs/ghidra_scripts_folder.png "ghidra_scripts")

## Credits
Some functions were added in the AskJOE, but we did not create them. Let us give the proper credit.

- [Stack Strings](https://github.com/reb311ion/replica/blob/fede41b9afd2ef5e33c860ce114e8a24193751ac/replica.py#L560)
- [Crypto Constants](https://github.com/reb311ion/replica/blob/fede41b9afd2ef5e33c860ce114e8a24193751ac/replica.py#L527)
- [Capa Explorer](https://github.com/mandiant/capa/blob/master/capa/ghidra/capa_explorer.py)