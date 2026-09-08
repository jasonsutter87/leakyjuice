// build-target.mjs — produce dist/, the deployable BENCHMARK target.
//
// The point of LeakyJuice as an out-of-distribution benchmark is that the target
// and its ground truth NEVER travel together. This build copies only the runtime
// files a hunter's server needs, and then asserts the answer key is nowhere in the
// output. If ground truth leaks in, the build fails loudly rather than shipping a
// contaminated target.
//
// Usage:  npm run build:target   →   dist/
//   Deploy dist/ as a Node app:  cd dist && npm start   (BENCHMARK mode by default)

import fs from 'node:fs';
import path from 'node:path';

const ROOT = process.cwd();
const DIST = path.join(ROOT, 'dist');

// Allowlist: exactly what the running target needs. Everything else — holdout/,
// scripts/, data/ (regenerated on boot), .git, node_modules — is excluded.
const INCLUDE = ['server.js', 'lib', 'public'];

// Never allowed in the output, by name or by content signature.
const FORBIDDEN_NAMES = ['answers.json', 'VULNS.md', 'BLUEPRINT.md', 'grade.mjs', 'holdout'];
// Signatures unique to the ground-truth files' STRUCTURE (not UI copy or source comments).
const FORBIDDEN_SIGNATURES = ['honest_abstain_traps', '"expected": "abstain"', '"verify": {', '"sink":'];

function rmrf(p) { fs.rmSync(p, { recursive: true, force: true }); }
function copyRec(src, dst) {
  const st = fs.statSync(src);
  if (st.isDirectory()) {
    fs.mkdirSync(dst, { recursive: true });
    for (const name of fs.readdirSync(src)) copyRec(path.join(src, name), path.join(dst, name));
  } else {
    fs.copyFileSync(src, dst);
  }
}
function walk(dir, out = []) {
  for (const name of fs.readdirSync(dir)) {
    const full = path.join(dir, name);
    if (fs.statSync(full).isDirectory()) walk(full, out); else out.push(full);
  }
  return out;
}

// 1. clean + copy the allowlist
rmrf(DIST);
fs.mkdirSync(DIST, { recursive: true });
for (const item of INCLUDE) {
  const src = path.join(ROOT, item);
  if (!fs.existsSync(src)) { console.error(`✗ missing required target file: ${item}`); process.exit(1); }
  copyRec(src, path.join(DIST, item));
}

// 2. write a minimal, spoiler-free package.json (no training/grade/build scripts)
const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
fs.writeFileSync(path.join(DIST, 'package.json'), JSON.stringify({
  name: pkg.name, version: pkg.version, description: pkg.description,
  type: pkg.type, private: true,
  scripts: { start: 'node --experimental-sqlite --no-warnings server.js' },
  engines: pkg.engines,
}, null, 2) + '\n');

// 3. a target-facing README with no answer key
fs.writeFileSync(path.join(DIST, 'README.md'),
  '# LeakyJuice (target build)\n\n' +
  'A gadget shop that leaks on purpose. Black-box benchmark target — no map, no answer key.\n\n' +
  '```bash\nnpm start   # → http://localhost:4060\n```\n\n' +
  'Investigate. Form a hypothesis. Prove it. Every confirmed bug drops a `FLAG{lj_…}`.\n');

// 4. ASSERT: no ground truth made it into dist/
const files = walk(DIST);
const failures = [];
for (const f of files) {
  const rel = path.relative(DIST, f);
  if (FORBIDDEN_NAMES.some((n) => rel.split(path.sep).includes(n) || path.basename(f) === n)) {
    failures.push(`forbidden file present: ${rel}`);
  }
}
// content scan (skip binaries by extension)
const TEXT = /\.(js|mjs|json|md|html|css|txt|svg)$/i;
for (const f of files) {
  if (!TEXT.test(f)) continue;
  const body = fs.readFileSync(f, 'utf8');
  for (const sig of FORBIDDEN_SIGNATURES) {
    if (body.includes(sig)) failures.push(`answer-key signature "${sig}" found in ${path.relative(DIST, f)}`);
  }
}

if (failures.length) {
  console.error('✗ build-target: ground truth leaked into dist/ — refusing to ship:');
  for (const x of failures) console.error('   - ' + x);
  process.exit(1);
}

console.log(`✓ dist/ built — ${files.length} files, no ground truth. Deploy as a Node app (npm start = BENCHMARK mode).`);
