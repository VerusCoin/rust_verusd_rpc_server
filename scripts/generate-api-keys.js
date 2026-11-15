#!/usr/bin/env node

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const keyIds = [
  "verus-mobile",
  "verus-mobile-1",
  "verus-mobile-2",
  "verus-mobile-3",
  "verus-mobile-4",
  "verus-mobile-5",
  "verus-mobile-dev",
  "verus-mobile-dev-1",
  "verus-mobile-dev-2",
  "verus-mobile-dev-3",
  "verus-mobile-dev-4",
  "verus-mobile-dev-5",
  "valu-mobile",
  "valu-mobile-1",
  "valu-mobile-2",
  "valu-mobile-3",
  "valu-mobile-4",
  "valu-mobile-5",
  "verus-desktop",
  "verus-desktop-1",
  "verus-desktop-2",
  "verus-desktop-3",
  "verus-desktop-4",
  "verus-desktop-5",
  "verus-desktop-testnet",
  "verus-desktop-testnet-1",
  "verus-desktop-testnet-2",
  "verus-desktop-testnet-3",
  "verus-desktop-testnet-4",
  "verus-desktop-testnet-5",
  "verus-express",
  "verus-express-1",
  "verus-express-2",
  "verus-express-3",
  "verus-express-4",
  "verus-express-5",
  "verus-dev-key-1",
  "verus-dev-key-2",
  "verus-dev-key-3",
  "verus-dev-key-4",
  "verus-dev-key-5",
  "verus-dev-key-6",
  "verus-dev-key-7",
  "verus-dev-key-8",
  "verus-dev-key-9",
  "verus-dev-key-10",
];

const args = process.argv.slice(2);
const force = args.includes("--force");
const outputArgIndex = args.findIndex((arg) => arg === "--output");
const outputPath =
  outputArgIndex >= 0 && args[outputArgIndex + 1]
    ? path.resolve(args[outputArgIndex + 1])
    : path.resolve(process.cwd(), "api-keys.txt");

if (fs.existsSync(outputPath) && !force) {
  console.error(
    `Refusing to overwrite existing file: ${outputPath}\n` +
      "Re-run with --force to replace it or use --output <path>."
  );
  process.exit(1);
}

const lines = keyIds.map((keyId) => {
  const apiKey = crypto.randomBytes(32).toString("hex");
  return `${keyId} = "${apiKey}"`;
});

fs.writeFileSync(outputPath, `${lines.join("\n")}\n`, { mode: 0o600 });

console.log(`Generated ${keyIds.length} API keys in ${outputPath}`);
