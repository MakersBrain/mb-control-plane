#!/usr/bin/env node
/**
 * Copy the brand icons out of the package and into `static/`.
 *
 * The icons cannot simply be imported by `+layout.svelte`, and the reason is
 * `src/routes/+layout.ts`: this app is `ssr = false, prerender = false`, a pure
 * SPA shell. Anything declared in `<svelte:head>` therefore lands in the DOM
 * only after hydration, so an imported favicon means the browser asks for
 * `/favicon.ico`, gets a 404, and shows its default icon until the bundle
 * boots. `app.html` is the only place an icon link exists before JavaScript
 * runs, and a link in `app.html` has to resolve to a real file under `static/`.
 *
 * So these are copies -- but generated ones. They are gitignored, they are
 * rewritten from `@makersbrain/brand` on every `dev` and `build`, and there is
 * no version of them that a person can edit and forget to push upstream. That
 * is the distinction that matters: the old `styles/` copies were committed
 * files kept equal to their source by a check, and these are build outputs.
 *
 *     node scripts/sync-icons.mjs
 */

import { copyFileSync, mkdirSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const here = dirname(fileURLToPath(import.meta.url));
const staticDir = join(here, '..', 'static');

// Resolved through the package's own exports rather than by reaching into
// node_modules, so a change to its layout is the package's business.
const ICONS = {
	'favicon.svg': '@makersbrain/brand/logo/favicon.svg',
	'favicon-32.png': '@makersbrain/brand/logo/favicon-32.png',
	'apple-touch-icon.png': '@makersbrain/brand/logo/favicon-180.png'
};

mkdirSync(staticDir, { recursive: true });

for (const [name, specifier] of Object.entries(ICONS)) {
	copyFileSync(require.resolve(specifier), join(staticDir, name));
}

console.log(`synced ${Object.keys(ICONS).length} brand icons into static/`);
