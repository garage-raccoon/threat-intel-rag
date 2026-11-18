# Blind Haiku evaluation (research.md D38)

A no-API-cost stand-in for `scripts/evaluate.py --claude`: what does the answer model do with unanswerable questions that get past the retrieval checks?

## Method
1. **Questions:**
   - Every unanswerable question that the retrieval checks did **not** stop: 2 from the approved set, 10 from the held-out set.
   - **6 answerable control questions,** randomly sampled (seed `20261118`) from held-out questions that were found and not stopped. If the model declined everything, the controls would show it.
2. **Same inputs as `ask.py`:** each question was paired with the same 5 passages `ask.py` would send, and the same system prompt (`ask.SYSTEM_PROMPT`).
3. **Blinded:**
   - The items were shuffled and given neutral IDs (Q01–Q18).
   - `blind_items.json` holds no labels. The answer key (`answer_key.json`) was kept in a separate folder that the agent was told not to read.
4. **The run:** a Claude Code subagent on the Haiku model read only `blind_items.json`, answered each item under the system prompt, and labeled its own answer `answered` / `declined` / `partial`.
5. **Scoring:** the labels were matched against the key afterwards (by the main session, not the agent).

## Files
| File | What it is |
|---|---|
| `blind_items.json` | What the agent saw: system prompt + 18 questions with their passages |
| `answer_key.json` | Q-ID → test-set ID, role (unanswerable / control) and expected IDs |
| `haiku_answers.json` | The agent's answers, labels and cited IDs, unedited |

## Exact instructions given to the agent
> You are standing in for the answer model of a retrieval-augmented Q&A system about MITRE ATT&CK. Your job is to answer questions exactly as that system's answer model would, then record what you did.
>
> Read ONLY this one file: `…/blind_eval/blind_items.json`. Do not read, list, or search any other file or directory, and do not use the web. Everything you need is in that file.
>
> The file contains "system_prompt" (the instructions the answer model runs under; follow them for every item as if they were your own system prompt) and "items" (18 questions, each with an "id", a "question", and "passages": the 5 passages the search step retrieved for it).
>
> For EACH item independently:
> 1. Treat its passages as the only knowledge you have. Do not use outside knowledge, and do not use other items' passages.
> 2. Write the answer the system would show the user, following the system prompt: answer only from the passages, name the ATT&CK ID of each technique you discuss, and if the passages don't contain the answer, say so plainly instead of guessing. Keep each answer under 120 words.
> 3. Classify your own answer with exactly one label: "answered" (the passages answer the question and you answered it from them), "declined" (you said the passages don't contain the answer, and gave no substantive answer), or "partial" (you said the passages don't fully cover the question, but still offered related information from them).
>
> Write a JSON list to `haiku_answers.json`: `{"id", "label", "cited_ids", "answer", "reason"}` per item.

## Limits: this is a stand-in, not the production system
- **Not the API call `ask.py` makes.** It's Haiku running as a Claude Code subagent. The exact model version and effort setting may differ from `claude-haiku-5-5` at `effort: medium`.
- **No API citations.** "Cited IDs" are the IDs the model named in its own text, not Citations-API blocks.
- **Labels are self-reported.** The main session read all 18 answers and found every label consistent with its answer text.
- **Small sample:** 12 unanswerable + 6 controls.
