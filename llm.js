/**
 * LLM provider for the response engine (Milestone 1).
 *
 * Talks to a local Ollama server by default — no API costs, no data leaves
 * the machine. Requests only reach this module after every AAP check has
 * passed (key, device, live session, scope, limits, LLM access).
 *
 * Config (env):
 *   LLM_PROVIDER        ollama (default) | none
 *   OLLAMA_URL          http://localhost:11434
 *   LLM_MODEL           default model            (llama3.2:3b)
 *   LLM_MODEL_<CAT>     per-category override, e.g. LLM_MODEL_CODING=qwen2.5-coder:7b
 *   LLM_MAX_TOKENS      max reply tokens         (512)
 *   LLM_TIMEOUT_MS      whole-request timeout    (90000)
 */

'use strict';

const CATEGORIES = ['general', 'math', 'text', 'coding', 'cyber', 'design', 'data'];

const config = {
  provider: (process.env.LLM_PROVIDER || 'ollama').toLowerCase(),
  url: (process.env.OLLAMA_URL || 'http://localhost:11434').replace(/\/$/, ''),
  model: process.env.LLM_MODEL || 'llama3.2:3b',
  routes: Object.fromEntries(
    CATEGORIES.map((c) => [c, process.env[`LLM_MODEL_${c.toUpperCase()}`]]).filter(([, m]) => m)
  ),
  maxTokens: Number(process.env.LLM_MAX_TOKENS) || 512,
  timeoutMs: Number(process.env.LLM_TIMEOUT_MS) || 90000,
};

const BASE_PROMPT = [
  'You are the assistant behind an account-bound API. Be accurate, concise, and practical.',
  'Prefer short paragraphs and bullet points. Use fenced code blocks for code.',
  'If you are unsure, say so instead of guessing.',
].join(' ');

// Scope-aware system prompts: the request was already classified into a
// category the caller's key is allowed to use.
const CATEGORY_PROMPTS = {
  general: 'Answer general questions helpfully. Keep answers brief unless asked for detail.',
  math: 'Solve maths step by step, then give the final answer clearly.',
  text: 'Help with writing and text transformation tasks.',
  coding: 'You are a senior software engineer. Give working, idiomatic code with a brief explanation. Point out bugs and edge cases.',
  cyber: [
    'You are a defensive security engineer.',
    'Explain vulnerabilities, detection, hardening, secure design, and incident response.',
    'Do not provide working exploits, malware, or step-by-step instructions for attacking systems the user does not own;',
    'redirect such requests to defensive guidance or authorised testing practice.',
  ].join(' '),
  design: 'You are a product designer. Give concrete UI/UX, colour, typography, and accessibility guidance.',
  data: 'You are a data analyst. Explain methods clearly, show formulas or code (SQL, Python, spreadsheets) when useful.',
};

function enabled() {
  return config.provider === 'ollama';
}

function modelFor(category) {
  return config.routes[category] || config.model;
}

/** Provider health for dashboards/CLI: never throws. */
async function status() {
  if (!enabled()) return { provider: 'none', enabled: false, reachable: false };
  try {
    const r = await fetch(`${config.url}/api/tags`, { signal: AbortSignal.timeout(2000) });
    const tags = r.ok ? await r.json() : { models: [] };
    const installed = new Set((tags.models || []).map((m) => m.name));
    const wanted = [...new Set([config.model, ...Object.values(config.routes)])];
    return {
      provider: 'ollama',
      enabled: true,
      reachable: r.ok,
      model: config.model,
      routes: config.routes,
      missing: wanted.filter((m) => !installed.has(m)),
    };
  } catch {
    return { provider: 'ollama', enabled: true, reachable: false, model: config.model, routes: config.routes };
  }
}

/**
 * Stream a chat completion. Calls onDelta(text) for each chunk and resolves
 * with { reply, model, usage: { input, output } }. Throws on failure so the
 * engine can fall back to local answers.
 */
async function chat({ category, history = [], message, onDelta }) {
  if (!enabled()) throw new Error('LLM disabled');
  const model = modelFor(category);
  const messages = [
    { role: 'system', content: `${BASE_PROMPT} ${CATEGORY_PROMPTS[category] || CATEGORY_PROMPTS.general}` },
    ...history.map((h) => ({ role: h.role, content: h.content })),
    { role: 'user', content: message },
  ];
  const res = await fetch(`${config.url}/api/chat`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      model,
      messages,
      stream: true,
      options: { num_predict: config.maxTokens, temperature: 0.4 },
    }),
    signal: AbortSignal.timeout(config.timeoutMs),
  });
  if (!res.ok || !res.body) throw new Error(`Ollama HTTP ${res.status}`);

  // Ollama streams newline-delimited JSON objects.
  let reply = '';
  let usage = { input: 0, output: 0 };
  let buf = '';
  const decoder = new TextDecoder();
  for await (const chunk of res.body) {
    buf += decoder.decode(chunk, { stream: true });
    let nl;
    while ((nl = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, nl).trim();
      buf = buf.slice(nl + 1);
      if (!line) continue;
      const evt = JSON.parse(line);
      if (evt.error) throw new Error(evt.error);
      const text = (evt.message && evt.message.content) || '';
      if (text) {
        reply += text;
        if (onDelta) onDelta(text);
      }
      if (evt.done) usage = { input: evt.prompt_eval_count || 0, output: evt.eval_count || 0 };
    }
  }
  if (!reply.trim()) throw new Error('Empty LLM reply');
  return { reply, model, usage };
}

module.exports = { config, enabled, status, chat, modelFor };
