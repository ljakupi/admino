import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import yaml from 'yaml';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SRC = path.resolve(__dirname, '../../config/permissions.yaml');
const DEST = path.resolve(__dirname, '../src/data/permissions.json');

if (!fs.existsSync(SRC)) {
  console.warn(`permissions: ${SRC} not found, skipping`);
  process.exit(0);
}

const parsed = yaml.parse(fs.readFileSync(SRC, 'utf8'));
fs.mkdirSync(path.dirname(DEST), { recursive: true });
fs.writeFileSync(DEST, JSON.stringify(parsed, null, 2));
console.log(`permissions: ${SRC} -> ${DEST}`);
