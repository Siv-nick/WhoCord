"""
web_services
------------
Business logic extracted out of web_app.py.

Each module in this package owns one concern and can be exercised
without a Flask test client:

- ``config_actions.ConfigActionDispatcher`` — turns a
  ``{"action": "...", ...}`` payload into a config mutation and a
  response body.
- ``jobs.JobRegistry`` — owns every piece of live job state: the
  registry itself, cancel events, worker thread handles, and pending
  pivot responses. Every access is lock-protected.
- ``chat.active_chat_system_prompt`` / ``build_chat_context`` — pure
  builders for the LLM chat prompt.
- ``llm_models.fetch_models_for_provider`` — queries the active
  provider's model list, with a hardcoded fallback.

Deliberately not re-exported at the package level — importing
``web_services`` should not drag in every dependency. Import the
specific module you need.
"""