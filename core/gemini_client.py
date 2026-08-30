"""One shared Gemini API client, used by core.pre_request_analysis (Step 2
risk/complexity analysis), core.model_pipeline (Step 4 generation), and
core.auditing_engine (Step 6 auditing) — a single place reading
GEMINI_API_KEY and constructing the client, rather than three.
"""

import os

from google import genai

_client = None


def get_client():
    global _client
    if _client is None:
        _client = genai.Client(api_key=os.environ["GEMINI_API_KEY"])
    return _client
