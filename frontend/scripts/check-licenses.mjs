import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const scriptDir = dirname(fileURLToPath(import.meta.url));
const frontendDir = join(scriptDir, '..');
const repoRoot = join(frontendDir, '..');
const aboutToml = join(repoRoot, 'about.toml');
const frontendPackageJson = join(frontendDir, 'package.json');

const aboutContents = readFileSync(aboutToml, 'utf8');
const acceptedBlock = aboutContents.match(/accepted\s*=\s*\[([\s\S]*?)\]/);

if (!acceptedBlock) {
  console.error(`Could not find accepted licenses in ${aboutToml}`);
  process.exit(1);
}

const rawAcceptedLicenses = [...acceptedBlock[1].matchAll(/"([^"]+)"/g)].map(
  ([, license]) => license,
);

if (rawAcceptedLicenses.length === 0) {
  console.error(`No accepted licenses found in ${aboutToml}`);
  process.exit(1);
}

// cargo-about rejects modern SPDX `-only` / `-or-later` forms in its allow
// list, so about.toml uses the deprecated bare identifiers (e.g. "GPL-3.0").
// npm ecosystems standardize on the modern forms, so accept both here.
const deprecatedSpdxFamily = /^(?:L?GPL|AGPL|GFDL)-\d+\.\d+$/;
const acceptedLicenses = [
  ...new Set(
    rawAcceptedLicenses.flatMap((license) =>
      deprecatedSpdxFamily.test(license)
        ? [license, `${license}-only`, `${license}-or-later`]
        : [license],
    ),
  ),
];

const frontendPackage = JSON.parse(readFileSync(frontendPackageJson, 'utf8'));
const frontendLicense = frontendPackage.license;

if (!frontendLicense) {
  console.error(
    `Package "${frontendPackage.name}@${frontendPackage.version}" is missing a license field.`,
  );
  process.exit(1);
}

if (!acceptedLicenses.includes(frontendLicense)) {
  console.error(
    `Package "${frontendPackage.name}@${frontendPackage.version}" is licensed under "${frontendLicense}" which is not permitted.`,
  );
  process.exit(1);
}

const result = spawnSync(
  './node_modules/.bin/license-checker-rseidelsohn',
  [
    '--start',
    '.',
    '--excludePrivatePackages',
    '--onlyAllow',
    acceptedLicenses.join(';'),
    '--summary',
  ],
  {
    cwd: frontendDir,
    stdio: 'inherit',
  },
);

if (result.error) {
  console.error(result.error.message);
  process.exit(1);
}

process.exit(result.status ?? 1);
