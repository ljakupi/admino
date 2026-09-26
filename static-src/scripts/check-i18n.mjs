#!/usr/bin/env node
/**
 * check-i18n — CI/local check that the `en`, `de` and `fr` i18n catalogs
 * (issue #144: PWA internationalization) have identical key sets and
 * identical `{placeholder}` names per key.
 *
 * Usage: `node scripts/check-i18n.mjs [localesDir]`. `localesDir` defaults
 * to `../src/i18n/locales`, resolved relative to this script, so the
 * result never depends on the working directory it is invoked from.
 *
 * Node stdlib only (no dependencies) and never `import`/`eval`/`require`s
 * the catalogs: it reads each `<locale>.ts` file as *text* and parses it
 * with a small, strict, literal-only tokenizer/parser, so the catalogs
 * stay pure data and this check can never execute arbitrary catalog code.
 *
 * Accepted catalog format: a single `export const <name> = { ... }`
 * (optionally typed, e.g. `export const de: Record<string, Message> = {`,
 * or followed by `satisfies Record<string, Message>`) whose object literal
 * holds only:
 *   - keys: single- or double-quoted strings (with backslash escapes) or
 *     bare identifiers;
 *   - values: single- or double-quoted string literals, or a nested plural
 *     object literal (`{ one: '...', other: '...' }`) whose own values must
 *     themselves be string literals.
 * `//` and `/* *\/` comments and trailing commas are allowed anywhere.
 * Template literals, identifiers, calls, spreads or any other expression
 * as a value are rejected as parse errors.
 *
 * Reports (one line per problem, to stderr, exit 1; never an uncaught
 * exception/stack trace): parse errors and non-literal values (naming the
 * file), duplicate keys, missing/extra keys (naming the key and locale),
 * `{placeholder}` set mismatches (a plural message's placeholder set is the
 * union over all its forms), and plural objects with no `other` form or an
 * invalid LDML category. On success: one line to stdout, exit 0.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const LOCALES = ['en', 'de', 'fr'];
const PLURAL_CATEGORIES = new Set(['zero', 'one', 'two', 'few', 'many', 'other']);
const PLACEHOLDER_RE = /\{([A-Za-z_][A-Za-z0-9_]*)\}/g;

// --- Tokenizer --------------------------------------------------------------

/**
 * Turns `source` into a flat list of significant tokens (whitespace and
 * comments are skipped, never emitted). Token shapes:
 *   - `{ type: 'string', value }` — decoded content of a '...' or "..." literal
 *   - `{ type: 'template', value }` — a `...` template literal (rejected as a value)
 *   - `{ type: 'ident', value }` — a bare identifier / keyword
 *   - `{ type: 'punct', value }` — one of `{ } ( ) [ ] < > : , ; .` or `=`
 *   - `{ type: 'other', value }` — anything else (numbers, operators, ...),
 *     kept only so the parser can reject it as an invalid key/value.
 * Never throws: an unterminated string/template yields a token holding
 * whatever was read, so the caller can still report a clean parse error.
 */
function tokenize(source) {
  const tokens = [];
  const n = source.length;
  let i = 0;

  while (i < n) {
    const ch = source[i];

    if (ch === ' ' || ch === '\t' || ch === '\n' || ch === '\r') {
      i += 1;
      continue;
    }

    if (ch === '/' && source[i + 1] === '/') {
      i += 2;
      while (i < n && source[i] !== '\n') i += 1;
      continue;
    }

    if (ch === '/' && source[i + 1] === '*') {
      i += 2;
      while (i < n && !(source[i] === '*' && source[i + 1] === '/')) i += 1;
      i = Math.min(i + 2, n);
      continue;
    }

    if (ch === "'" || ch === '"') {
      const quote = ch;
      let j = i + 1;
      let value = '';
      while (j < n && source[j] !== quote) {
        if (source[j] === '\\' && j + 1 < n) {
          value += source[j + 1];
          j += 2;
        } else {
          value += source[j];
          j += 1;
        }
      }
      tokens.push({ type: 'string', value });
      i = j + 1;
      continue;
    }

    if (ch === '`') {
      let j = i + 1;
      while (j < n && source[j] !== '`') {
        j += source[j] === '\\' && j + 1 < n ? 2 : 1;
      }
      tokens.push({ type: 'template', value: source.slice(i, Math.min(j + 1, n)) });
      i = j + 1;
      continue;
    }

    if (/[A-Za-z_$]/.test(ch)) {
      let j = i + 1;
      while (j < n && /[A-Za-z0-9_$]/.test(source[j])) j += 1;
      tokens.push({ type: 'ident', value: source.slice(i, j) });
      i = j;
      continue;
    }

    if ('{}()[]<>:,;.='.includes(ch)) {
      tokens.push({ type: 'punct', value: ch });
      i += 1;
      continue;
    }

    tokens.push({ type: 'other', value: ch });
    i += 1;
  }

  return tokens;
}

// --- Catalog parser ----------------------------------------------------------

function isPunct(token, value) {
  return Boolean(token) && token.type === 'punct' && token.value === value;
}

/**
 * Parses the `export const <name> = { ... }` catalog declaration out of
 * `source`. Returns `{ entries, errors }`: `entries` is a `Map<string,
 * string | Record<string,string>>` of every successfully parsed key
 * (parsing stops at the first structural error, but keys already parsed
 * are kept); `errors` holds one human-readable line per problem, each
 * naming `fileLabel`.
 */
function parseCatalog(source, fileLabel) {
  const tokens = tokenize(source);
  const errors = [];
  const entries = new Map();

  let declStart = -1;
  for (let i = 0; i < tokens.length - 1; i += 1) {
    if (tokens[i].type === 'ident' && tokens[i].value === 'export' && tokens[i + 1].type === 'ident' && tokens[i + 1].value === 'const') {
      declStart = i;
      break;
    }
  }
  if (declStart === -1) {
    errors.push(`${fileLabel}: no "export const" catalog declaration found`);
    return { entries, errors };
  }

  let pos = declStart + 2;
  const nameToken = tokens[pos];
  if (!nameToken || nameToken.type !== 'ident') {
    errors.push(`${fileLabel}: expected a catalog name after "export const"`);
    return { entries, errors };
  }
  pos += 1;

  while (pos < tokens.length && !isPunct(tokens[pos], '=')) pos += 1;
  if (pos >= tokens.length) {
    errors.push(`${fileLabel}: expected "=" in the catalog declaration`);
    return { entries, errors };
  }
  pos += 1;

  if (!isPunct(tokens[pos], '{')) {
    errors.push(`${fileLabel}: expected "{" to start the catalog object literal`);
    return { entries, errors };
  }

  const openIndex = pos;
  let depth = 0;
  let closeIndex = -1;
  for (let j = openIndex; j < tokens.length; j += 1) {
    if (isPunct(tokens[j], '{')) depth += 1;
    else if (isPunct(tokens[j], '}')) {
      depth -= 1;
      if (depth === 0) {
        closeIndex = j;
        break;
      }
    }
  }
  if (closeIndex === -1) {
    errors.push(`${fileLabel}: unterminated catalog object literal (missing closing "}")`);
    return { entries, errors };
  }

  const body = tokens.slice(openIndex + 1, closeIndex);
  let p = 0;

  while (p < body.length) {
    if (isPunct(body[p], ',')) {
      p += 1;
      continue;
    }

    const keyToken = body[p];
    if (!keyToken || (keyToken.type !== 'string' && keyToken.type !== 'ident')) {
      errors.push(`${fileLabel}: expected a key (quoted string or identifier)`);
      break;
    }
    const key = keyToken.value;
    p += 1;

    if (!isPunct(body[p], ':')) {
      errors.push(`${fileLabel}: expected ":" after key "${key}"`);
      break;
    }
    p += 1;

    const valueToken = body[p];
    if (!valueToken) {
      errors.push(`${fileLabel}: expected a value for key "${key}"`);
      break;
    }

    let value;
    if (valueToken.type === 'string') {
      value = valueToken.value;
      p += 1;
    } else if (isPunct(valueToken, '{')) {
      const parsed = parsePluralObject(body, p, key, fileLabel);
      if (parsed.error) {
        errors.push(parsed.error);
        break;
      }
      value = parsed.value;
      p = parsed.nextIndex;
    } else {
      errors.push(
        `${fileLabel}: invalid value for key "${key}": expected a quoted string literal or a plural object`,
      );
      break;
    }

    if (entries.has(key)) {
      errors.push(`${fileLabel}: duplicate key "${key}"`);
    } else {
      entries.set(key, value);
    }

    if (isPunct(body[p], ',')) {
      p += 1;
    } else if (p < body.length) {
      errors.push(`${fileLabel}: expected "," or "}" after the value for key "${key}"`);
      break;
    }
  }

  return { entries, errors };
}

/** Parses a `{ category: '...', ... }` plural object starting at `body[openIndex]`. */
function parsePluralObject(body, openIndex, key, fileLabel) {
  let depth = 0;
  let closeIndex = -1;
  for (let j = openIndex; j < body.length; j += 1) {
    if (isPunct(body[j], '{')) depth += 1;
    else if (isPunct(body[j], '}')) {
      depth -= 1;
      if (depth === 0) {
        closeIndex = j;
        break;
      }
    }
  }
  if (closeIndex === -1) {
    return { error: `${fileLabel}: unterminated plural object for key "${key}"` };
  }

  const inner = body.slice(openIndex + 1, closeIndex);
  const value = {};
  let q = 0;
  while (q < inner.length) {
    if (isPunct(inner[q], ',')) {
      q += 1;
      continue;
    }

    const categoryToken = inner[q];
    if (!categoryToken || (categoryToken.type !== 'ident' && categoryToken.type !== 'string')) {
      return { error: `${fileLabel}: invalid plural category in key "${key}"` };
    }
    const category = categoryToken.value;
    q += 1;

    if (!isPunct(inner[q], ':')) {
      return { error: `${fileLabel}: expected ":" after plural category "${category}" in key "${key}"` };
    }
    q += 1;

    const formToken = inner[q];
    if (!formToken || formToken.type !== 'string') {
      return { error: `${fileLabel}: ${key}.${category} is not a quoted string literal` };
    }
    value[category] = formToken.value;
    q += 1;

    if (isPunct(inner[q], ',')) q += 1;
  }

  return { value, nextIndex: closeIndex + 1 };
}

// --- Cross-catalog checks -----------------------------------------------------

/** Every `{placeholder}` name used across all string forms of a catalog value (sorted, de-duplicated). */
function placeholdersOf(value) {
  const forms = typeof value === 'string' ? [value] : Object.values(value);
  const names = new Set();
  for (const form of forms) {
    for (const match of form.matchAll(PLACEHOLDER_RE)) names.add(match[1]);
  }
  return [...names].sort();
}

function compareCatalogs(enEntries, entries, locale) {
  const problems = [];

  for (const key of enEntries.keys()) {
    if (!entries.has(key)) problems.push(`Missing key "${key}" in locale ${locale} (present in en)`);
  }
  for (const key of entries.keys()) {
    if (!enEntries.has(key)) problems.push(`Extra key "${key}" in locale ${locale} (not present in en)`);
  }

  for (const key of enEntries.keys()) {
    if (!entries.has(key)) continue;
    const enNames = placeholdersOf(enEntries.get(key));
    const names = placeholdersOf(entries.get(key));
    if (enNames.join(',') !== names.join(',')) {
      problems.push(
        `Placeholder mismatch for key "${key}" in locale ${locale}: en has {${enNames.join(', ')}}, ${locale} has {${names.join(', ')}}`,
      );
    }
  }

  return problems;
}

function validatePlurals(entries, locale) {
  const problems = [];
  for (const [key, value] of entries) {
    if (typeof value === 'string') continue;
    if (typeof value.other !== 'string') {
      problems.push(`Plural key "${key}" in locale ${locale} has no "other" form`);
    }
    for (const category of Object.keys(value)) {
      if (!PLURAL_CATEGORIES.has(category)) {
        problems.push(`Plural key "${key}" in locale ${locale} has invalid category "${category}"`);
      }
    }
  }
  return problems;
}

// --- Entry point ---------------------------------------------------------------

function defaultLocalesDir() {
  return fileURLToPath(new URL('../src/i18n/locales', import.meta.url));
}

function main() {
  const dirArg = process.argv[2];
  const localesDir = dirArg ? path.resolve(process.cwd(), dirArg) : defaultLocalesDir();

  const problems = [];
  const catalogs = new Map();

  for (const locale of LOCALES) {
    const filePath = path.join(localesDir, `${locale}.ts`);
    if (!fs.existsSync(filePath)) {
      problems.push(`Missing locale file: ${locale}.ts`);
      continue;
    }
    const source = fs.readFileSync(filePath, 'utf8');
    const { entries, errors } = parseCatalog(source, `${locale}.ts`);
    problems.push(...errors);
    catalogs.set(locale, entries);
  }

  const en = catalogs.get('en');
  if (en) {
    for (const locale of LOCALES) {
      if (locale === 'en') continue;
      const entries = catalogs.get(locale);
      if (entries) problems.push(...compareCatalogs(en, entries, locale));
    }
    for (const [locale, entries] of catalogs) {
      problems.push(...validatePlurals(entries, locale));
    }
  }

  if (problems.length > 0) {
    for (const problem of problems) process.stderr.write(`${problem}\n`);
    process.exitCode = 1;
    return;
  }

  const keyCount = en ? en.size : 0;
  process.stdout.write(`i18n catalogs OK: en, de, fr match (${keyCount} keys).\n`);
  process.exitCode = 0;
}

try {
  main();
} catch (error) {
  process.stderr.write(`check-i18n crashed: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
}
