// Builds the plugin workspace (plugins/Cargo.toml): the lc-plugin-host loader
// and every plugin library. Each library is then copied next to its
// plugin.toml under the platform file name the manifest's [library] path
// resolves to (linuxinfo → linuxinfo.dll / liblinuxinfo.so /
// liblinuxinfo.dylib), so development discovery of the repository plugins/
// directory and the release bundle see the same layout.
//
//   bun scripts/build.mjs            # debug build
//   bun scripts/build.mjs --release  # release build (bundles, packs)
//   bun scripts/build.mjs --plugin linuxinfo # one DLL, keep an active host running
//
// Always build from the committed plugin lockfile.
import { spawnSync } from 'node:child_process';
import { copyFileSync, existsSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const release = process.argv.includes('--release');
const workspace = fileURLToPath(new URL('..', import.meta.url));
const cargoArgs = ['build', '--locked', '--manifest-path', join(workspace, 'Cargo.toml')];
const pluginIndex = process.argv.indexOf('--plugin');
const selected = pluginIndex === -1 ? null : process.argv[pluginIndex + 1];
if (pluginIndex !== -1) {
  if (!selected || !/^[a-z][a-z0-9-]*$/.test(selected) || !existsSync(join(workspace, selected, 'plugin.toml'))) {
    console.error('[build-plugins] --plugin requires a bundled plugin directory name');
    process.exit(1);
  }
  const manifest = Bun.TOML.parse(readFileSync(join(workspace, selected, 'Cargo.toml'), 'utf8'));
  if (typeof manifest.package?.name !== 'string') {
    console.error('[build-plugins] selected plugin has no Cargo package name');
    process.exit(1);
  }
  cargoArgs.push('--package', manifest.package.name);
}
if (release) cargoArgs.push('--release');

const build = spawnSync('cargo', cargoArgs, { stdio: 'inherit' });
if (build.status !== 0) process.exit(build.status ?? 1);

const output = join(workspace, 'target', release ? 'release' : 'debug');
const [prefix, suffix] =
  process.platform === 'win32' ? ['', '.dll'] : process.platform === 'darwin' ? ['lib', '.dylib'] : ['lib', '.so'];

let staged = 0;
for (const entry of readdirSync(workspace, { withFileTypes: true })) {
  if (selected !== null && entry.name !== selected) continue;
  const manifestPath = join(workspace, entry.name, 'plugin.toml');
  if (!entry.isDirectory() || !existsSync(manifestPath)) continue;
  const manifest = Bun.TOML.parse(readFileSync(manifestPath, 'utf8'));
  const name = manifest.library?.path;
  if (typeof name !== 'string' || /[\\/]|\.(dll|so|dylib)$/i.test(name)) {
    console.error(`[build-plugins] ${manifestPath}: [library] path must be the crate's library name`);
    process.exit(1);
  }
  const fileName = `${prefix}${name}${suffix}`;
  const built = join(output, fileName);
  if (!existsSync(built)) {
    console.error(`[build-plugins] ${built} was not built; is ${entry.name} a workspace member with [lib] name = "${name}"?`);
    process.exit(1);
  }
  copyFileSync(built, join(workspace, entry.name, fileName));
  staged += 1;
}
console.log(`[build-plugins] staged ${staged} plugin libraries from ${output}`);
