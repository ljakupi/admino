"""Dev-only performance tools that enforce the GH-244 budgets (not pytest tests).

Two command-line modules, run with ``python -m`` (never collected by pytest:
no ``test_`` prefix):

- ``tests.perf.chat_budgets`` (``make perf``): the server-side budgets, measured
  in-process against a throwaway ``postgres:16`` container and a fake LLM.
- ``tests.perf.ttft`` (``make ttft``): the manual time-to-first-token and
  tokens/s measurement of the Infomaniak models, with the operator's token.

They live under ``tests/`` because they are the budget gate: implementers can't
change them to make a budget pass.

Security notes: neither tool prints a password, DSN, token, message or reply
text; see each module's docstring.
"""
