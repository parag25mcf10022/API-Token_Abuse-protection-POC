/**
 * Per-model prices, for cost tracking (Milestone 1).
 *
 * Prices are USD per million tokens, Anthropic first-party API rates. Cache
 * writes use the 5-minute TTL (1.25 × input). Local Ollama models are free.
 *
 * Override or add models with LLM_PRICES (JSON), e.g.
 *   LLM_PRICES='{"claude-opus-5-5":{"input":4,"output":20,"cacheRead":0.2}}'
 * A model with no known price is metered for tokens but its cost is null.
 */

'use strict';

const PRICES = {
  'claude-fable-5-1': { input: 10, output: 50, cacheRead: 0.25 },
  'claude-fable-5': { input: 10, output: 50 },
  'claude-opus-5-5': { input: 4, output: 20, cacheRead: 0.2 },
  'claude-opus-5': { input: 5, output: 25 },
  'claude-opus-4-8': { input: 5, output: 25 },
  'claude-sonnet-5-5': { input: 2, output: 10, cacheRead: 0.2 },
  'claude-sonnet-5': { input: 2, output: 10 },
  'claude-haiku-5-5': { input: 0.1, output: 0.5 },
  'claude-haiku-4-5': { input: 1, output: 5 },
};

try {
  const extra = process.env.LLM_PRICES ? JSON.parse(process.env.LLM_PRICES) : {};
  for (const [model, p] of Object.entries(extra)) {
    if (p && Number.isFinite(p.input) && Number.isFinite(p.output)) PRICES[model] = p;
  }
} catch {
  console.warn('[pricing] LLM_PRICES is not valid JSON; using built-in prices.');
}

const isHosted = (model) => /^claude-/.test(String(model || ''));

/** Price for a model, or null if unknown. Local models cost nothing. */
function priceFor(model) {
  if (!isHosted(model)) return { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 };
  const p = PRICES[model];
  if (!p) return null;
  return {
    input: p.input,
    output: p.output,
    cacheRead: p.cacheRead !== undefined ? p.cacheRead : p.input * 0.1,
    cacheWrite: p.cacheWrite !== undefined ? p.cacheWrite : p.input * 1.25,
  };
}

/**
 * USD cost of one model attempt: { input, output, cacheRead, cacheWrite }
 * token counts. Returns null when the model's price is unknown.
 */
function costOf(model, u) {
  const p = priceFor(model);
  if (!p) return null;
  return (
    ((u.input || 0) * p.input +
      (u.output || 0) * p.output +
      (u.cacheRead || 0) * p.cacheRead +
      (u.cacheWrite || 0) * p.cacheWrite) /
    1e6
  );
}

module.exports = { PRICES, priceFor, costOf, isHosted };
