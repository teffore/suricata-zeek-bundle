# purple_agent_pkg — extracted modules for the purple-team agent.
#
# The orchestrator + prompts + report builders still live in the top-level
# purple_agent.py for now. Over successive refactor passes, pure-function /
# side-effect-isolated code moves here so it can be imported and tested
# without pulling in claude-agent-sdk.
#
# First extraction (refactor-split): enrich.py — constants + verdict/
# confidence/tool normalization + findings loading/enrichment.
