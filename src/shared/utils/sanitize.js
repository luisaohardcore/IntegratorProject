// src/shared/utils/sanitize.js
// Mitigation for T-01 (XSS) — sanitizes user text inputs before use

const HTML_TAG_PATTERN   = /<[^>]*>/g;
const SCRIPT_PATTERN     = /javascript:/gi;
const EVENT_ATTR_PATTERN = /on\w+\s*=/gi;

/**
 * Strips HTML tags and dangerous patterns from a string.
 * Applied to all user-supplied text fields before submission.
 */
export function sanitizeText(value) {
  if (typeof value !== 'string') return value;
  return value
    .replace(HTML_TAG_PATTERN, '')
    .replace(SCRIPT_PATTERN, '')
    .replace(EVENT_ATTR_PATTERN, '')
    .trim();
}

/**
 * Recursively sanitizes all string fields in an object.
 */
export function sanitizePayload(obj) {
  if (typeof obj !== 'object' || obj === null) return obj;
  return Object.fromEntries(
    Object.entries(obj).map(([k, v]) => [
      k,
      typeof v === 'string' ? sanitizeText(v) : v,
    ])
  );
}
