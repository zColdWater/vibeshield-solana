#!/usr/bin/env node
import { scanTarget } from "../src/scanner.mjs";

const args = process.argv.slice(2);
const jsonFlag = args.includes("--json");
const filtered = args.filter(a => a !== "--json" && a !== "scan");
const target = filtered[0];

if (!target || args.includes("--help") || args.includes("-h")) {
  console.log(`VibeShield Solana Edition v1.0.0 — Zero-Dependency Solana Mainnet Security Scanner

Usage:
  npx vibeshield-solana <MINT_OR_PROGRAM_OR_WALLET_OR_URL> [--json]

Examples:
  npx vibeshield-solana 2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo   # PayPal USD (SPL Token-2022)
  npx vibeshield-solana EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v   # Circle USDC (SPL Token)
  npx vibeshield-solana JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4    # Jupiter v6 BPF Program
  npx vibeshield-solana https://omnipulse-x402.appwrite.network/v1/defi/yield-radar`);
  process.exit(target ? 0 : 1);
}

try {
  const report = await scanTarget(target);
  if (jsonFlag) {
    console.log(JSON.stringify(report, null, 2));
    process.exit(0);
  }
  console.log(`\n🛡️  VibeShield Solana v1.0.0 — Security Audit Report`);
  console.log(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
  console.log(`Target   : ${report.target}`);
  console.log(`Kind     : ${report.kind}`);
  console.log(`Score    : ${report.score}/100 (Grade ${report.grade})`);
  if (report.slot) console.log(`Slot     : ${report.slot} (${report.durationMs}ms via ${report.rpcUsed})`);
  if (report.summary) {
    console.log(`Summary  : ${JSON.stringify(report.summary)}`);
  }
  console.log(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
  for (const f of report.findings) {
    const icon = f.severity === "PASS" ? "✅" : f.severity === "INFO" ? "ℹ️" : f.severity === "LOW" ? "🟡" : f.severity === "MEDIUM" ? "🟠" : "🔴";
    console.log(`${icon} [${f.severity}] ${f.id} — ${f.title}`);
    console.log(`   ${f.detail}`);
    if (f.severity !== "PASS") console.log(`   ↳ Fix: ${f.remediation}`);
  }
  console.log("");
} catch (err) {
  console.error(`Error: ${err.message}`);
  process.exit(1);
}
