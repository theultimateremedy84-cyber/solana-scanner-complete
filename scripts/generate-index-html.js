#!/usr/bin/env node
/**
 * Post-build script: generates dist/client/index.html from the Vite manifest.
 *
 * TanStack Start with SSR disabled does not emit an index.html during the
 * client build. This script reads dist/client/.vite/manifest.json, finds the
 * entry-point JS (and any associated CSS), and writes a minimal SPA shell that
 * Caddy can serve for every route.
 */

import { readFileSync, writeFileSync } from "fs";
import { resolve, dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const clientDir = resolve(__dirname, "../dist/client");
const manifestPath = resolve(clientDir, ".vite/manifest.json");

let manifest;
try {
  manifest = JSON.parse(readFileSync(manifestPath, "utf-8"));
} catch {
  // Vite 5+ may place the manifest at dist/client/manifest.json
  const fallback = resolve(clientDir, "manifest.json");
  manifest = JSON.parse(readFileSync(fallback, "utf-8"));
}

// Collect all entry-point JS files and their associated CSS
const entryScripts = [];
const entryStyles = [];

for (const chunk of Object.values(manifest)) {
  if (!chunk.isEntry) continue;
  if (chunk.file?.endsWith(".js") || chunk.file?.endsWith(".mjs")) {
    entryScripts.push(chunk.file);
  }
  if (Array.isArray(chunk.css)) {
    entryStyles.push(...chunk.css);
  }
}

if (entryScripts.length === 0) {
  console.error("generate-index-html: no entry-point JS found in manifest");
  process.exit(1);
}

const styleLinks = entryStyles
  .map((f) => `  <link rel="stylesheet" href="/${f}" />`)
  .join("\n");

const scriptTags = entryScripts
  .map((f) => `  <script type="module" src="/${f}"></script>`)
  .join("\n");

const html = `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Lovable App</title>
${styleLinks}
  </head>
  <body>
    <div id="root"></div>
${scriptTags}
  </body>
</html>
`;

const outPath = resolve(clientDir, "index.html");
writeFileSync(outPath, html, "utf-8");
console.log(`generate-index-html: wrote ${outPath}`);
