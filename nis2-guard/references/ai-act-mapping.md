# AI Act: technical readiness and repository evidence

Regulation (EU) 2024/1689. The legal risk tier depends on the real deployment context,
not on the code. Never certify compliance; frame findings as "technical alignment with
the AI Act's transparency, logging and oversight controls". Application dates are
phased and have been subject to change: check the current timeline before stating it.

## Risk profile (estimate from code, then confirm with the user)

- **Prohibited practices (Art. 5):** e.g. social scoring, manipulative techniques,
  untargeted scraping of facial images. If you see signs of these, stop and say so.
- **High-risk (Art. 6, Annex III):** employment and hiring, credit scoring, access to
  education and exam evaluation, essential public and private services, insurance
  pricing, law enforcement, migration, justice, critical infrastructure; also AI as a
  safety component of regulated products. Medical triage and diagnosis usually fall under
  product rules for medical devices.
- **Limited risk (Art. 50):** chatbots, voice agents, generated or manipulated content:
  transparency duties.
- **Minimal risk:** everything else; voluntary codes of conduct.

| Art. | Requirement | What to look for in code | Scanner rules |
|------|-------------|--------------------------|---------------|
| 10 | Data governance | Provenance tracking, validation and PII scrubbing in training and RAG ingestion | None (manual) |
| 12 | Record-keeping | Structured log per AI call: timestamp, model id/version, input hash, tools executed, output or hash | AIACT-NO-AI-AUDIT-LOG |
| 14 | Human oversight | Approval step, override and confidence thresholds before high-impact actions | AIACT-HIGH-RISK-INDICATOR |
| 15 | Accuracy, robustness, cybersecurity | Static system prompts, delimited user input, schema-validated output, no execution of output, rate limits, timeouts, fallback | AIACT-PROMPT-INJECTION-RISK, AIACT-LLM-OUTPUT-EXEC, EXEC-DANGEROUS |
| 50 | Transparency | UI notice that users interact with an AI; marking of generated content; API flag | AIACT-NO-DISCLOSURE |

The AI rules only run when the project uses an AI SDK (imports or manifests: OpenAI,
Anthropic, LangChain, LlamaIndex, Google GenAI, Mistral, Cohere, Ollama, transformers,
LiteLLM, Vercel AI SDK).

## Secure patterns to propose

- **Disclosure:** a visible "You are chatting with an AI assistant" notice, labels on
  generated content and an `ai_generated: true` field or `X-AI-Generated` header.
- **Audit event:** `{ts, request_id, model, model_version, input_sha256, tools_called,
  output_sha256, decision, reviewer}` sent to an append-only store; no raw personal data.
- **Oversight:** high-impact decisions go to a `pending_review` state; a human approves or
  overrides; low-confidence outputs are never auto-applied.
- **Robustness:** system prompt as a constant; user input in the user turn inside clear
  delimiters; output parsed with a strict schema (JSON schema / Pydantic) and checked
  against an allow-list of actions; timeouts, retries and a fallback answer when the
  provider fails.

## Outside the code

- Risk classification of the actual deployment.
- Technical documentation (Art. 11, Annex IV) and quality management for high-risk systems.
- Fundamental Rights Impact Assessment where applicable (Art. 27).
- Registration in the EU database for high-risk systems where required (Art. 49).
- AI literacy measures for staff (Art. 4).
