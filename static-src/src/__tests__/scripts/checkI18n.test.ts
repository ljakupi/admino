// @vitest-environment node
/**
 * `check:i18n` script tests (issue #144: PWA internationalization).
 *
 * `static-src/scripts/check-i18n.mjs [localesDir]` is the dependency-free
 * (Node stdlib only) CI check that the `en`, `de` and `fr` catalogs have
 * identical key sets and identical `{placeholder}` names per key. It reads
 * `en.ts`, `de.ts` and `fr.ts` WITHOUT executing them, with a strict literal
 * parser: keys are quoted strings or bare identifiers, values are quoted
 * string literals or plural objects, comments and trailing commas are allowed,
 * and anything else (template literals, identifiers, calls) is rejected, so
 * catalogs stay pure data. `localesDir` defaults to `src/i18n/locales`,
 * resolved relative to the script, so the working directory doesn't matter.
 *
 * Contract: exit 0 with a success line on stdout when the catalogs match;
 * exit 1 with one line per problem on stderr otherwise (no crash/stack
 * trace). Every failure case asserts that a stderr line names the specific
 * key, locale or file, so a missing or crashing script can't pass. Each test
 * writes its fixture catalogs to a fresh temp dir; nothing touches the
 * network.
 */
/// <reference types="node" />
import { describe, it, expect, afterEach } from 'vitest';
import { spawnSync, type SpawnSyncReturns } from 'node:child_process';
import fs from 'node:fs';
import { isBuiltin } from 'node:module';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const SCRIPT = fileURLToPath(new URL('../../../scripts/check-i18n.mjs', import.meta.url));
const PACKAGE_JSON = fileURLToPath(new URL('../../../package.json', import.meta.url));

type Locale = 'en' | 'de' | 'fr';

// --- Fixtures -------------------------------------------------------------

/**
 * Valid catalog bodies that exercise every accepted form: single-, double-
 * and un-quoted keys, escapes, `//` inside a string, comments holding quotes
 * and braces, plural objects and trailing commas.
 */
const BASE: Record<Locale, string> = {
  en: String.raw`
  // Navigation. Placeholders look like {name}; it's fine to mention them here.
  'nav.chat': 'Chat',
  "greeting": "Hello {name}",
  farewell: 'Bye', /* a block comment with a ' quote and a } brace */
  'quote.escaped': 'It\'s {name}\'s turn',
  'link.docs': "See https://example.com/{path} · docs",
  'items.count': {
    one: '{count} item',
    other: '{count} items', // trailing comment
  },`,
  de: String.raw`
  'nav.chat': 'Chat',
  "greeting": "Hallo {name}",
  farewell: 'Tschüss',
  'quote.escaped': 'Jetzt ist {name} dran',
  'link.docs': 'Siehe https://example.com/{path} · Doku',
  'items.count': {
    one: '{count} Element',
    other: '{count} Elemente',
  },`,
  fr: String.raw`
  'nav.chat': 'Discussion',
  "greeting": "Bonjour \"{name}\"",
  farewell: 'Au revoir',
  'quote.escaped': 'C\'est au tour de {name}',
  'link.docs': 'Voir https://example.com/{path} · docs',
  'items.count': {
    one: '{count} élément',
    other: '{count} éléments',
  },`,
};

/** A catalog file as the app writes it; `en` uses the `satisfies` form. */
function catalogSource(locale: Locale, body: string): string {
  const header = [
    "import type { Message } from '../core';",
    '',
    `/* ${locale} fixture catalog. */`,
  ];
  const declaration =
    locale === 'en'
      ? ['export const en = {', body, '} satisfies Record<string, Message>;']
      : [`export const ${locale}: Record<string, Message> = {`, body, '};'];
  return [...header, ...declaration, ''].join('\n');
}

const tempDirs: string[] = [];

/** Write the given catalog bodies (omitted locales get no file) to a fresh dir. */
function writeCatalogs(bodies: Partial<Record<Locale, string>>): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'i18n-check-'));
  tempDirs.push(dir);
  for (const [locale, body] of Object.entries(bodies) as Array<[Locale, string]>) {
    fs.writeFileSync(path.join(dir, `${locale}.ts`), catalogSource(locale, body), 'utf8');
  }
  return dir;
}

/** The base bodies plus extra entries per locale. */
function withEntries(extra: Partial<Record<Locale, string>>): Record<Locale, string> {
  return {
    en: BASE.en + (extra.en ?? ''),
    de: BASE.de + (extra.de ?? ''),
    fr: BASE.fr + (extra.fr ?? ''),
  };
}

function runCheck(args: string[], cwd?: string): SpawnSyncReturns<string> {
  return spawnSync(process.execPath, [SCRIPT, ...args], { encoding: 'utf8', cwd, timeout: 20_000 });
}

function escapeRegExp(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** Matches `needle` as a whole word (e.g. `de`, not the `de` in `loader`). */
function word(needle: string): RegExp {
  return new RegExp(`(^|[^A-Za-z0-9_])${escapeRegExp(needle)}([^A-Za-z0-9_]|$)`);
}

/**
 * The script's outcome, reduced to what the contract promises: the exit
 * status, whether one stderr line names every needle, and whether stderr
 * holds a crash stack trace instead of problem lines.
 */
function report(result: SpawnSyncReturns<string>, needles: Array<string | RegExp>) {
  const lines = (result.stderr ?? '').split('\n');
  const named = lines.some((line) =>
    needles.every((needle) => (typeof needle === 'string' ? line.includes(needle) : needle.test(line))),
  );
  return { status: result.status, named, crashed: /^\s+at\s/m.test(result.stderr ?? '') };
}

const REPORTED = { status: 1, named: true, crashed: false };

afterEach(() => {
  for (const dir of tempDirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
});

// --- The script -----------------------------------------------------------

describe('check-i18n script', () => {
  it('ships at static-src/scripts/check-i18n.mjs', () => {
    expect(fs.existsSync(SCRIPT)).toBe(true);
  });

  it('is exposed as npm run check:i18n', () => {
    const pkg = JSON.parse(fs.readFileSync(PACKAGE_JSON, 'utf8')) as { scripts?: Record<string, string> };

    expect(pkg.scripts?.['check:i18n']).toMatch(/\bnode\s+(\.\/)?scripts\/check-i18n\.mjs\b/);
  });

  it('imports Node built-in modules only', () => {
    const source = fs.readFileSync(SCRIPT, 'utf8');
    // Static imports (single- or multi-line), bare imports, dynamic imports, require().
    const specifiers = [
      ...source.matchAll(/^\s*import\s[^;]*?\bfrom\s*['"]([^'"]+)['"]/gm),
      ...source.matchAll(/^\s*import\s*['"]([^'"]+)['"]/gm),
      ...source.matchAll(/\bimport\(\s*['"]([^'"]+)['"]\s*\)/g),
      ...source.matchAll(/\brequire\(\s*['"]([^'"]+)['"]\s*\)/g),
    ].map((match) => match[1]);

    expect(specifiers.filter((specifier) => !isBuiltin(specifier))).toEqual([]);
  });
});

describe('check-i18n passing catalogs', () => {
  it('exits 0 with a success line on stdout for matching catalogs', () => {
    const result = runCheck([writeCatalogs(BASE)]);

    expect({
      status: result.status,
      stdout: result.stdout.trim() !== '',
      stderr: result.stderr.trim(),
    }).toEqual({ status: 0, stdout: true, stderr: '' });
  });

  it('exits 0 when plural categories differ per locale but the placeholders match', () => {
    const dir = writeCatalogs(
      withEntries({
        en: `\n  'fixture.files': { one: '{count} file', other: '{count} files' },`,
        de: `\n  'fixture.files': { one: '{count} Datei', other: '{count} Dateien' },`,
        fr: `\n  'fixture.files': { one: '{count} fichier', many: '{count} de fichiers', other: '{count} fichiers' },`,
      }),
    );

    expect(runCheck([dir]).status).toBe(0);
  });

  it('checks the real catalogs by default, from any working directory', () => {
    const elsewhere = fs.mkdtempSync(path.join(os.tmpdir(), 'i18n-check-cwd-'));
    tempDirs.push(elsewhere);

    const result = runCheck([], elsewhere);

    expect({ status: result.status, stderr: result.stderr.trim() }).toEqual({ status: 0, stderr: '' });
  });
});

describe('check-i18n failing catalogs', () => {
  it('reports a key missing in de, naming the key and de', () => {
    const dir = writeCatalogs(
      withEntries({
        en: `\n  'fixture.onlyInEn': 'Only in English',`,
        fr: `\n  'fixture.onlyInEn': 'Seulement en anglais',`,
      }),
    );

    expect(report(runCheck([dir]), ['fixture.onlyInEn', word('de')])).toEqual(REPORTED);
  });

  it('reports an extra key in fr, naming the key and fr', () => {
    const dir = writeCatalogs(withEntries({ fr: `\n  'fixture.extraInFr': 'En trop',` }));

    expect(report(runCheck([dir]), ['fixture.extraInFr', word('fr')])).toEqual(REPORTED);
  });

  it('reports a placeholder mismatch, naming the key', () => {
    const dir = writeCatalogs(
      withEntries({
        en: `\n  'fixture.greet': 'Hello {name}',`,
        de: `\n  'fixture.greet': 'Hallo {name}',`,
        fr: `\n  'fixture.greet': 'Bonjour {nom}',`,
      }),
    );

    expect(report(runCheck([dir]), ['fixture.greet'])).toEqual(REPORTED);
  });

  it('reports a placeholder mismatch inside a plural message, naming the key', () => {
    const dir = writeCatalogs(
      withEntries({
        en: `\n  'fixture.pluralNames': { one: '{count} file', other: '{count} files' },`,
        de: `\n  'fixture.pluralNames': { one: '{count} Datei', other: '{anzahl} Dateien' },`,
        fr: `\n  'fixture.pluralNames': { one: '{count} fichier', other: '{count} fichiers' },`,
      }),
    );

    expect(report(runCheck([dir]), ['fixture.pluralNames'])).toEqual(REPORTED);
  });

  it('reports a plural message without an other form, naming the key', () => {
    const dir = writeCatalogs(
      withEntries({
        en: `\n  'fixture.noOther': { one: '{count} file', other: '{count} files' },`,
        de: `\n  'fixture.noOther': { one: '{count} Datei', other: '{count} Dateien' },`,
        fr: `\n  'fixture.noOther': { one: '{count} fichier' },`,
      }),
    );

    expect(report(runCheck([dir]), ['fixture.noOther'])).toEqual(REPORTED);
  });

  it.each([
    ['a template literal', '`Hallo`'],
    ['an identifier', 'someIdentifier'],
    ['a function call', "translate('fixture.dynamic')"],
  ])('rejects %s as a value, naming the file', (_label, expression) => {
    const dir = writeCatalogs(
      withEntries({
        en: `\n  'fixture.dynamic': 'Hello',`,
        de: `\n  'fixture.dynamic': ${expression},`,
        fr: `\n  'fixture.dynamic': 'Bonjour',`,
      }),
    );

    expect(report(runCheck([dir]), ['de.ts'])).toEqual(REPORTED);
  });

  it('reports a duplicate key inside one catalog, naming the key', () => {
    const dir = writeCatalogs(
      withEntries({
        en: `\n  'fixture.dup': 'One',`,
        de: `\n  'fixture.dup': 'Eins',\n  "fixture.dup": 'Zwei',`,
        fr: `\n  'fixture.dup': 'Un',`,
      }),
    );

    expect(report(runCheck([dir]), ['fixture.dup'])).toEqual(REPORTED);
  });

  it('reports a missing locale file, naming fr', () => {
    const dir = writeCatalogs({ en: BASE.en, de: BASE.de });

    expect(report(runCheck([dir]), [word('fr')])).toEqual(REPORTED);
  });
});
