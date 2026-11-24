import test from "node:test";
import assert from "node:assert/strict";
import { encodeBase58, isValidSolanaAddress, decodeProgramDataHeader, scanTarget } from "../src/scanner.mjs";

test("isValidSolanaAddress validates Base58 pubkeys", () => {
  assert.equal(isValidSolanaAddress("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"), true);
  assert.equal(isValidSolanaAddress("2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo"), true);
  assert.equal(isValidSolanaAddress("https://solana.com"), false);
  assert.equal(isValidSolanaAddress("0x4Ac77B91D00E4E7707868FfAbeF8a544637FE6b0"), false);
});

test("decodeProgramDataHeader decodes 45-byte BPFLoaderUpgradeab1e header", () => {
  const buf = Buffer.alloc(45);
  buf.writeUInt32LE(3, 0);
  buf.writeBigUInt64LE(470226883n, 4);
  buf[12] = 0; // immutable
  const parsed = decodeProgramDataHeader(buf.toString("base64"));
  assert.equal(parsed.lastDeployedSlot, 470226883);
  assert.equal(parsed.immutable, true);
  assert.equal(parsed.upgradeAuthority, null);
  assert.equal(encodeBase58(Buffer.alloc(32, 0)), "1".repeat(32));
});

test("live Solana Mainnet RPC scan of PYUSD Token-2022 mint detects permanentDelegate", async () => {
  const res = await scanTarget("2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo");
  assert.equal(res.kind, "spl_token_2022_mint");
  assert.ok(res.summary.extensions.includes("permanentDelegate"));
  assert.ok(res.findings.some(f => f.id === "SOL-T22-001"));
});

test("live Solana Mainnet RPC scan of Jupiter v6 program decodes upgradeAuthority via 45B slice", async () => {
  const res = await scanTarget("JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4");
  assert.equal(res.kind, "bpf_upgradeable_program");
  assert.equal(res.summary.programDataAddress, "4Ec7ZxZS6Sbdg5UGSLHbAnM7GQHp2eFd4KYWRexAipQT");
  assert.equal(res.summary.upgradeAuthority, "CvQZZ23qYDWF2RUpxYJ8y9K4skmuvYEEjH7fK58jtipQ");
  assert.ok(res.summary.lastDeployedSlot > 400000000);
});
