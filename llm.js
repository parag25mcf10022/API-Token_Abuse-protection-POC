/**
 * LLM providers for the response engine (Milestone 1).
 *
 * Two providers, chosen per model:
 *   - Ollama (default): local, no API costs, no data leaves the machine.
 *   - Anthropic Claude: any model id starting with "claude-". Hosted, so
 *     prompts are sent to Anthropic and cost money (tracked per model, see
 *     pricing.js). Used only when ANTHROPIC_API_KEY is set.
 * Requests only reach this module after every AAP check has passed (key,
 * device, live session, scope, limits, LLM access).
 *
 * Config (env):
 *   LLM_PROVIDER        ollama (default) | anthropic | none
 *                       (anthropic makes Claude the default model)
 *   OLLAMA_URL          http://localhost:11434
 *   LLM_MODEL           default model  (llama3.2:3b; claude-opus-5-5 with anthropic)
 *   LLM_MODEL_<CAT>     per-category model, from either provider. With Ollama,
 *                       coding defaults to qwen2.5-coder:7b
 *                       (set LLM_MODEL_CODING=none to use the default model)
 *   LLM_MAX_TOKENS      max reply tokens for Ollama        (1024)
 *   LLM_TIMEOUT_MS      whole-request timeout              (90000)
 *   ANTHROPIC_API_KEY   enables Claude models
 *   CLAUDE_MAX_TOKENS   max reply tokens for Claude, thinking included (16000)
 *   CLAUDE_EFFORT       low | medium (default) | high | xhigh | max
 *
 * A routed model that isn't available falls back to LLM_MODEL; if no model is
 * available at all, the engine answers locally.
 */

'use strict';

const Anthropic = require('@anthropic-ai/sdk').default;
const { costOf, isHosted } = require('./pricing');

const CATEGORIES = ['general', 'math', 'text', 'coding', 'cyber', 'design', 'data'];

const provider = (process.env.LLM_PROVIDER || 'ollama').toLowerCase();

// Built-in routing: with Ollama, code questions go to a code-tuned model.
const DEFAULT_ROUTES = provider === 'ollama' ? { coding: 'qwen2.5-coder:7b' } : {};

const config = {
  provider,
  url: (process.env.OLLAMA_URL || 'http://localhost:11434').replace(/\/$/, ''),
  model: process.env.LLM_MODEL || (provider === 'anthropic' ? 'claude-opus-5-5' : 'llama3.2:3b'),
  routes: Object.fromEntries(
    CATEGORIES.map((c) => [c, process.env[`LLM_MODEL_${c.toUpperCase()}`] || DEFAULT_ROUTES[c]])
      .filter(([, m]) => m && m.toLowerCase() !== 'none')
  ),
  maxTokens: Number(process.env.LLM_MAX_TOKENS) || 1024,
  timeoutMs: Number(process.env.LLM_TIMEOUT_MS) || 90000,
  claudeMaxTokens: Number(process.env.CLAUDE_MAX_TOKENS) || 16000,
  claudeEffort: (process.env.CLAUDE_EFFORT || 'medium').toLowerCase(),
};

const BASE_PROMPT = [
  'You are the assistant behind AAP, an account-bound API: a key only works while its owner is logged in',
  'to the web app, from devices they approved, within scopes and usage limits set by admins; stolen keys',
  'are auto-locked. Be accurate, concise, and practical.',
  'Prefer short paragraphs and bullet points. Use fenced code blocks for code.',
  'If you are unsure, say so instead of guessing.',
].join(' ');

// Scope-aware system prompts: the request was already classified into a
// category the caller's key is allowed to use. Kept byte-stable so Claude's
// prompt cache can reuse them.
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

const systemPrompt = (category) => `${BASE_PROMPT} ${CATEGORY_PROMPTS[category] || CATEGORY_PROMPTS.general}`;

function enabled() {
  return config.provider === 'ollama' || config.provider === 'anthropic';
}

const claudeConfigured = () => !!(process.env.ANTHROPIC_API_KEY || process.env.ANTHROPIC_AUTH_TOKEN);

let claude = null;
function claudeClient() {
  if (!claude) claude = new Anthropic({ timeout: config.timeoutMs, maxRetries: 1 });
  return claude;
}

// Installed Ollama models, refreshed at most once a minute, so a missing
// routed model falls back instead of failing the request.
let installed = { names: null, reachable: false, at: 0 };
async function installedModels() {
  if (installed.names && Date.now() - installed.at < 60000) return installed;
  try {
    const r = await fetch(`${config.url}/api/tags`, { signal: AbortSignal.timeout(2000) });
    const tags = r.ok ? await r.json() : { models: [] };
    installed = { names: new Set((tags.models || []).map((m) => m.name)), reachable: r.ok, at: Date.now() };
  } catch {
    installed = { names: new Set(), reachable: false, at: Date.now() };
  }
  return installed;
}

async function available(model) {
  if (isHosted(model)) return claudeConfigured();
  return (await installedModels()).names.has(model);
}

/** Model to use for a category: its route if available, else the default. */
async function modelFor(category) {
  const routed = config.routes[category];
  if (routed && (await available(routed))) return routed;
  if (await available(config.model)) return config.model;
  throw new Error('No LLM model available');
}

/** Provider health for dashboards/CLI: never throws, never reveals the API key. */
async function status() {
  if (!enabled()) return { provider: 'none', enabled: false, reachable: false };
  const wanted = [...new Set([config.model, ...Object.values(config.routes)])];
  const usesOllama = wanted.some((m) => !isHosted(m));
  const usesClaude = wanted.some(isHosted);
  const ollama = usesOllama ? await installedModels() : null;
  const missing = [];
  for (const m of wanted) if (!(await available(m))) missing.push(m);
  return {
    provider: [usesOllama && 'ollama', usesClaude && 'anthropic'].filter(Boolean).join(' + '),
    enabled: true,
    reachable: isHosted(config.model) ? claudeConfigured() : !!(ollama && ollama.reachable),
    model: config.model,
    routes: config.routes,
    missing,
    ...(usesClaude ? { anthropic: { configured: claudeConfigured(), effort: config.claudeEffort } } : {}),
  };
}

/**
 * Stream a chat completion. Calls onDelta(text) for each chunk and resolves
 * with { reply, model, usage: { input, output, cacheRead, cacheWrite, cost },
 * truncated }. cost is USD (0 for local models, null if the price is
 * unknown). Throws on failure so the engine can fall back to local answers.
 */
async function chat({ category, history = [], message, onDelta }) {
  if (!enabled()) throw new Error('LLM disabled');
  const model = await modelFor(category);
  const args = { model, category, history, message, onDelta };
  return isHosted(model) ? chatClaude(args) : chatOllama(args);
}

async function chatOllama({ model, category, history, message, onDelta }) {
  const messages = [
    { role: 'system', content: systemPrompt(category) },
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
  let usage = { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, cost: 0 };
  let truncated = false;
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
      if (evt.done) {
        usage = { ...usage, input: evt.prompt_eval_count || 0, output: evt.eval_count || 0 };
        truncated = evt.done_reason === 'length'; // hit LLM_MAX_TOKENS
      }
    }
  }
  if (!reply.trim()) throw new Error('Empty LLM reply');
  return { reply, model, usage, truncated };
}

// Claude Haiku has no server-side refusal fallback.
const supportsFallbacks = (model) => !/^claude-haiku-/.test(model);

async function chatClaude({ model, category, history, message, onDelta }) {
  // The Messages API needs the conversation to start with a user turn.
  const turns = history.map((h) => ({ role: h.role, content: h.content }));
  while (turns.length && turns[0].role !== 'user') turns.shift();

  const stream = claudeClient().beta.messages.stream({
    model,
    max_tokens: config.claudeMaxTokens,
    system: systemPrompt(category),
    messages: [...turns, { role: 'user', content: message }],
    output_config: { effort: config.claudeEffort },
    // Caches the conversation prefix, so follow-up turns re-read it at the
    // cache price. Prefixes under the model's minimum (~512 tokens) are
    // simply not cached, at no extra cost.
    cache_control: { type: 'ephemeral' },
    // If a safety classifier declines, Anthropic retries on the model it
    // recommends for that refusal category, in the same call.
    ...(supportsFallbacks(model)
      ? { betas: ['server-side-fallback-2026-07-01'], fallbacks: 'default' }
      : {}),
  });

  let reply = '';
  for await (const evt of stream) {
    if (evt.type === 'content_block_start' && evt.content_block.type === 'fallback') {
      // A declined partial answer was already streamed; mark the switch.
      const note = `\n\n[${evt.content_block.from.model} declined; continuing with ${evt.content_block.to.model}]\n\n`;
      reply = '';
      if (onDelta) onDelta(note);
    } else if (evt.type === 'content_block_delta' && evt.delta.type === 'text_delta') {
      reply += evt.delta.text;
      if (onDelta) onDelta(evt.delta.text);
    }
  }
  const msg = await stream.finalMessage();

  // usage.iterations holds every attempt (a declined model and its
  // fallback), each billed at its own model's rates. Top-level usage only
  // covers the attempt that produced the returned message.
  const attempts = msg.usage.iterations && msg.usage.iterations.length
    ? msg.usage.iterations.filter((it) => it.type === 'message' || it.type === 'fallback_message')
    : [msg.usage];
  const usage = { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, cost: 0 };
  for (const it of attempts) {
    const u = {
      input: it.input_tokens || 0,
      output: it.output_tokens || 0,
      cacheRead: it.cache_read_input_tokens || 0,
      cacheWrite: it.cache_creation_input_tokens || 0,
    };
    const c = costOf(it.model || msg.model || model, u);
    usage.input += u.input;
    usage.output += u.output;
    usage.cacheRead += u.cacheRead;
    usage.cacheWrite += u.cacheWrite;
    usage.cost = usage.cost === null || c === null ? null : usage.cost + c;
  }

  if (msg.stop_reason === 'refusal') {
    // The whole chain declined. Without any answer, let the engine fall back.
    if (!reply.trim()) {
      const err = new Error('Claude declined the request');
      err.usage = usage;
      err.model = msg.model;
      throw err;
    }
    const note = '\n\n[The model declined to continue this answer.]';
    reply += note;
    if (onDelta) onDelta(note);
  }
  if (!reply.trim()) throw new Error('Empty LLM reply');
  return { reply, model: msg.model || model, usage, truncated: msg.stop_reason === 'max_tokens' };
}

/** Longest reply any configured model may produce (for the cost guide). */
function maxReplyTokens() {
  const models = [config.model, ...Object.values(config.routes)];
  return Math.max(...models.map((m) => (isHosted(m) ? config.claudeMaxTokens : config.maxTokens)));
}

module.exports = { config, enabled, status, chat, modelFor, claudeConfigured, maxReplyTokens };
