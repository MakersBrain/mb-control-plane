import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';

const indexPath = new URL('../build/index.html', import.meta.url);
const html = await readFile(indexPath, 'utf8');
const scripts = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)];

if (scripts.length !== 1) {
	throw new Error(`expected one inline bootstrap script, found ${scripts.length}`);
}

const bootstrap = scripts[0][1];
const digest = createHash('sha256').update(bootstrap).digest('hex').slice(0, 16);
const filename = `bootstrap.${digest}.js`;
const bootstrapPath = new URL(`../build/_app/immutable/${filename}`, import.meta.url);

await writeFile(bootstrapPath, bootstrap);
await writeFile(
	indexPath,
	html.replace(scripts[0][0], `<script src="/_app/immutable/${filename}"></script>`),
);
