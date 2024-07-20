from enum import Enum


class Operation(Enum):
    PROMPT = "User Prompt."
    AI_TRIAGE = "AI Triage."
    EXPLAIN_FUNCTION = "Explain Function."
    EXPLAIN_SELECTION = "Explain Selection."
    BETTER_NAME = "Better Name."
    SIMPLIFY_CODE = "Simplify Code."
    STACK_STRINGS = "Stack Strings."
    XORS = "Search XORs."
    CRYPTO_CONSTS = "Crypto Consts."
    CAPA_ANALYSIS = "Capa Analysis."
