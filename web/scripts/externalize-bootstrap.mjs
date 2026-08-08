import { readFile, writeFile } from 'node:fs/promises';

const indexPath = new URL('../build/index.html', import.meta.url);
const bootstrapPath = new URL('../build/bootstrap.js', import.meta.url);
const html = await readFile(indexPath, 'utf8');
const scripts = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)];

if (scripts.length !== 1) {
	throw new Error(`expected one inline bootstrap script, found ${scripts.length}`);
}

await writeFile(bootstrapPath, scripts[0][1]);
await writeFile(
	indexPath,
	html.replace(scripts[0][0], '<script src="/bootstrap.js"></script>'),
);
