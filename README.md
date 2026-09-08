# AI Agent Security — Multi-Step Tool Attacks (Kaggle)

> A **red-teaming** competition hosted by **OpenAI · Google · IEEE** ($50,000 prize pool).
> The goal is defensive: find multi-step prompt attacks that make a tool-using LLM agent misbehave, so that these failure modes can be caught and defended against. This repo is my competition write-up and submission code.

**Status:** A retrospective on my entry to the AI Agent Security – Multi-Step Tool Attacks competition, written as a security-research post-mortem: what the competition set out to measure, the engineering I built to compete, why my best public score did not transfer to the private set, and — most importantly — what the whole exercise says about how to defend tool-using LLM agents.

This repository is a learning artifact. It documents attack classes and their defenses at a conceptual level; it is not a drop-in offensive toolkit.

---

## The problem in one sentence

You write an `attack.py` whose `AttackAlgorithm` class drives a tool-using LLM agent (GPT-OSS 20B / Gemma) through **multi-step prompts** that trick it into turning untrusted content into a dangerous tool call — and you return a set of **replayable** attack candidates. The graders replay your candidates in a fresh environment and re-score them. **They only trust the replay, never your self-reported results.**

This is a *code competition*: you submit code, not predictions. Final standing is decided on a private leaderboard.

The competition in one paragraph

Modern LLM "agents" don't just chat — they call tools: send email, POST to a URL, transfer funds, read files. Each tool call is an action in the real world, so a compromised or manipulated agent is a genuine security problem. This competition ran agents (GPT-OSS and Gemma variants) inside a sandbox behind a hidden guardrail, and scored how often a crafted user message could steer the agent into a policy-violating tool call. There were two scored leaderboards: a public board visible during the competition and a private board revealed at the end. The gap between them turned out to be the whole story.

Result & the honest headline
Public leaderboard: peaked around 88 (my notebooke V15 submission).
Private leaderboard: my highest-public approaches collapsed to ~0.

That gap is not a footnote — it is the single most instructive thing I took away from the competition, and I've made it the centerpiece of this write-up rather than hiding it. It is simultaneously a machine-learning generalization failure and a security-evaluation failure, and the two framings reinforce each other.

---

## Why this is a good problem to study

It's a clean, adversarial optimization loop under hard constraints, and the whole point is *defensive* — the attacks that win are exactly the ones defenders most need to know about. It also rewards reading the rules at the source-code level rather than the surface description, which turned out to be where most of the edge was.

---

## How the scoring actually works (read the SDK, not the data page)

The biggest single lever was reverse-engineering the official `aicomp_sdk` scoring code. Three things the source revealed that the competition's own Data page got wrong or left implicit:

1. **Message cap is 2,000 characters, not 10,000.** The Data page said 10k; `api.py` enforces `MAX_USER_MESSAGE_CHARS = 2000`. Building to the wrong cap would have silently truncated attacks.
2. **The scored "cell" hash is computed *only* from `tool_events`** — not from your user messages. So paraphrasing a prompt does **not** create a new scoring cell. Only changing a *tool-level* parameter (the URL domain in an `http.post`, a target file path, a `web.search` query, an email recipient) produces a fresh, separately-scored cell.
3. **Severity sums across all findings; there's no dedup.** Every candidate is replayed and scored independently.

Put together, these three facts define the whole playbook: **find one robust attack template, then parametrize it across many tool-level values to spawn many distinct scoring cells — which stacks both cell count and cumulative severity.**

---

## Approach

The submission (`attack.py`) has three parts:

**1. Template registry.** Each attack is a parametrized template that renders a chain of user messages. Parameters map to the exact tool-level fields the scorer hashes into a cell, so one template can generate hundreds of distinct scored cells.

**2. Go-Explore / archive search.** Probe a small, diverse seed set against the *live* target agent; replay-validate each with the official `eval_predicates`; keep only the chains that actually trigger a safety predicate. Confirmed templates are then **amplified** — re-rendered with many fresh parameter tuples, severity-first, up to the 2,000-candidate cap. Nothing is assumed about agent compliance; the environment's own trace is the source of truth.

**3. Optional offline LLM hook.** If a small model is attached locally, confirmed chains get paraphrased for extra diversity. If not, the hook silently no-ops — so the submission stays safe under the no-internet rule.

Every environment call is wrapped so that a single agent error can never abort the whole run.

---

## Validating the pipeline locally (before spending GPU budget)

I got the full SDK running locally (Python 3.10 + a compatibility shim, CPU-only) and used the official `eval_predicates` / `score_attack` to verify the whole **run → replay → score** chain end-to-end with a deterministic stand-in agent:

- **Permissive guardrail** (allow-all, pipeline sanity only): 23 candidates → 23 replay-validated findings, RAW = 668.
- **`OptimalGuardrail`** (close to the public leaderboard config): 0 hits — a deterministic agent can't break it, which *matches* the guardrail analysis (taint tracking + sensitive-target blocking). Breaking it requires a real, non-deterministic model.

> These numbers come from a crude deterministic stand-in, **not** the real models — they prove the *pipeline* works, not the *score*. Real leaderboard points require running GPT-OSS/Gemma on Kaggle. Getting that signal, then iterating with the 5-submissions/day budget, is the current step.

---
## Lesson 1 — The public/private gap as a generalization problem

The public board rewarded a narrow, surface-level pattern: get the agent to emit a specific recognizable sentinel through one tool channel, then maximize throughput of that one trick. Optimizing hard against that signal is textbook overfitting to a validation set — I was tuning against a proxy metric (public score) that measured pattern-matching against one guardrail configuration, not the underlying capability the private set actually tested.

When the private guardrail turned out to behave differently, everything tuned to the public signal generalized to nothing. The mechanism is exactly the same as a model that memorizes the leaderboard split: high in-distribution score, zero out-of-distribution robustness.

Takeaways that transfer to any ML work:

A high score against a single held-out signal is evidence about that signal, not about the real objective. Treat a leaderboard the way you'd treat a single validation fold.
The safe design under distribution shift is the one that relies on the robust, semantic property, not the brittle, surface one — which is also the lesson for defenders (below).
I should have spent more of my budget probing whether a technique relied on a general property vs. a public-board artifact before investing in throughput optimization of it.
## Lesson 2 — What the competition teaches about defending agents

Strip away the leaderboard and the competition is a catalogue of the ways tool-using agents get manipulated. Each attack class maps cleanly to a defense. This is the part I'd want a security team to read.

a) Confused-deputy actions — the durable vulnerability

The techniques that survived to the private set were confused-deputy ones: the agent has legitimate authority to perform an action (send an email, transfer a record), and the attacker's message tricks it into exercising that authority on the attacker's behalf. Surface content filtering doesn't stop this because the action itself is one the agent is allowed to take.

Defense: authorize by provenance and intent, not just content. Before a side-effectful tool call, the system should be able to answer "who actually requested this action, and were they entitled to it?" — treating instructions that arrive through tool outputs, retrieved documents, or untrusted message bodies as data, not commands. This is the exact principle behind capability-scoping and human-in-the-loop confirmation for irreversible actions.

b) Guardrails that inspect only part of a tool call

A recurring weakness was a guardrail that checked one field of a tool call (e.g. the destination url) while the sensitive payload rode in a different field (e.g. the request body). A clean-looking first argument sailed through while the actual exfiltration sat in the part nobody inspected.

Defense: validate the entire tool-call object — every argument, recursively — against policy, and monitor the output channel, not just the input prompt. Detecting exfiltration by watching what leaves the system (destinations, payload entropy, sentinel-like markers in any field) is more robust than trying to recognize a bad request up front.

c) Reasoning-suppression via chat-template / control-token forgery

The most technically interesting attack class forged model-specific chat-template control tokens so the model's tokenizer believed a reasoning turn had already completed — effectively skipping the step where the model might otherwise reconsider and refuse. This is a parser-level exploit, not a semantic instruction the model chooses to obey.

Defense: never let user-supplied text reach the model as trusted template structure. Special/control tokens in untrusted input must be escaped or stripped before templating, and the serving stack should validate that channel boundaries in a prompt were produced by the server, not the user. This is the LLM-serving analogue of SQL parameterization: keep data out of the control plane.

d) Distribution-shifted guardrails (again, from the defender's side)

The public/private gap means the public guardrail was, in effect, a weaker or differently-configured version of the real one. Attackers who overfit to it wasted their effort — which is a hint for defenders: evaluate a guardrail across multiple distributions and adversary strategies, and don't let a single benchmark stand in for robustness. A guardrail that looks strong on one attack distribution can be trivially bypassed on another.

## Top-2 solutions — defensive takeaways

I studied the disclosed 1st- and 2nd-place write-ups. Rather than reproduce their payloads, here is what each got right conceptually and what a defender should learn from it.

1st place — concluded through disciplined leaderboard probing that only the confused-deputy route survived on the private set, and spent its effort on throughput rather than on brittle tricks. Defensive lesson: the confused-deputy class is the one that generalizes, so it's the one defenses must prioritize; content filtering alone will not touch it.

2nd place — explicitly documented the same trap I fell into: an exfiltration route that dominated the public board did not pass the private guardrail, and they had to switch to the confused-deputy route late. They also found that a simple single-hop action beat an elaborate multi-hop one. Defensive lesson: attack sophistication ≠ attack robustness. The simplest action that exercises real authority is often the most durable, so defenses should focus on authority boundaries rather than on detecting complex multi-step chains.

The meta-lesson across both: the winning insight was empirical humility — probing what actually generalized instead of trusting the public signal. That is the same discipline I'm taking away for my own ML work.

## What I actually built

The score is only part of the work. The reusable engineering here is the harness, not the payloads:

Reverse-engineered the scoring SDK to understand exactly how findings were credited (how predicates were summed per trace, how the per-model budget worked, how the public score was aggregated as a mean across models). Understanding the objective precisely was worth more than any single technique.
Deadline-aware validation-fill loop. Instead of blindly emitting a batch of candidates and hoping they fire, the runner generates one candidate, replays it against the live environment, keeps it only if it fired, and repeats until a safety cushion before the deadline. This lifted fire-efficiency to ~100% and let the loop self-size to each model's real speed rather than under-filling on a conservative guess.
Per-model adaptive latency budgeting. run() never learns which model it's talking to, so the loop infers speed from observed latency and scales its safety margin accordingly — a fast model is allowed to run wider while a slow model gets full protection against a budget-overrun (which would void the whole submission).
Replay-safe sizing. Rather than a flat cushion, the runner accumulates each kept candidate's measured cost and stops before it would exceed the replay budget, keeping the submission valid while growing the returned set.
Variant-sweep harness. All the tuning knobs (margin, budget fraction, split thresholds) are single-source-substituted so many submission variants could be generated and swept systematically instead of hand-edited — the same backtest-then-parameter-sweep discipline I use for trading strategies.

These are the transferable skills: reading an unfamiliar system to find its true objective, building a deadline-aware live-validation loop under a hard wall-clock constraint, and running disciplined parameter sweeps.

## Repository layout

```
kaggle-ai-agent-security/
├── README.md      ← you are here
└── attack.py      the submission: AttackAlgorithm(AttackAlgorithmBase).run(env, config)
```

---

## Key constraints (all source-verified)

- Per-model budget **9,000 s**; **≤2,000** candidates; **≤32** messages/candidate; **≤2,000** chars/message.
- Submission runs with **internet off** → any LLM hook must use a locally-attached model.
- Scoring cell = hash of `tool_events` only → **diversity must come from tool parameters, not prompt wording.**
- 5 submissions/day; final score is the private leaderboard.

---

## Note on intent

This is a defensive security competition run by OpenAI, Google, and IEEE: the objective is to surface multi-step agent vulnerabilities so they can be patched. The code here is scoped to that competition's sandboxed evaluation environment and is shared to document my methodology.

## License

MIT.
