// VibeShield Solana Edition v1.0.0 — Zero-Dependency Solana Mainnet Security Engine
// Audits SPL Token & Token-2022 extensions, BPF Upgradeable Program authorities,
// Solana Actions & Blinks (actions.json), and x402 Solana Pay treasury ATAs.

const DEFAULT_RPCS = [
  "https://api.mainnet-beta.solana.com",
  "https://solana-rpc.publicnode.com"
];

const PROGRAMS = {
  SYSTEM: "11111111111111111111111111111111",
  SPL_TOKEN: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
  TOKEN_2022: "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",
  BPF_UPGRADEABLE: "BPFLoaderUpgradeab1e11111111111111111111111",
  BPF_LOADER_V2: "BPFLoader2111111111111111111111111111111111",
  SQUADS_V4: "SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf",
  SQUADS_V3: "SMPLecH534NA9acpos4G6x7uf3LWbCAwZQE9e8ZekMu",
  SPL_GOVERNANCE: "GovER5Lthms3bLBqWub97yVrMmEogzX7xNjdXpPPCVZw"
};

const KNOWN_MINTS = {
  USDC: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
  PYUSD: "2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo"
};

const B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

export function encodeBase58(bytes) {
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++;
  if (zeros === bytes.length) return "1".repeat(zeros);
  const digits = [];
  for (let i = zeros; i < bytes.length; i++) {
    let carry = bytes[i];
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j] << 8;
      digits[j] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }
  let out = "1".repeat(zeros);
  for (let i = digits.length - 1; i >= 0; i--) out += B58_ALPHABET[digits[i]];
  return out;
}

export function isValidSolanaAddress(input) {
  if (typeof input !== "string" || input.length < 32 || input.length > 44) return false;
  return /^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(input);
}

export async function solanaRpc(method, params, rpcs = DEFAULT_RPCS) {
  let lastErr = null;
  for (const url of rpcs) {
    try {
      const res = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
        signal: AbortSignal.timeout(8000)
      });
      if (!res.ok) throw new Error(`HTTP ${res.status} from ${url}`);
      const json = await res.json();
      if (json.error) throw new Error(json.error.message || JSON.stringify(json.error));
      return { result: json.result, rpcUsed: url };
    } catch (err) {
      lastErr = err;
    }
  }
  throw lastErr || new Error("All Solana RPC endpoints failed");
}

export function decodeProgramDataHeader(base64Str) {
  const buf = Buffer.from(base64Str, "base64");
  if (buf.length < 13) throw new Error("ProgramData buffer shorter than 13 bytes");
  const tag = buf.readUInt32LE(0);
  if (tag !== 3) throw new Error(`Unexpected UpgradeableLoaderState tag=${tag} (expected 3)`);
  const lastDeployedSlot = Number(buf.readBigUInt64LE(4));
  const hasAuthority = buf[12] === 1;
  let upgradeAuthority = null;
  if (hasAuthority && buf.length >= 45) {
    upgradeAuthority = encodeBase58(buf.subarray(13, 45));
  }
  return { lastDeployedSlot, immutable: !hasAuthority, upgradeAuthority };
}

function scoreFindings(findings) {
  let penalty = 0;
  for (const f of findings) {
    if (f.severity === "CRITICAL") penalty += 28;
    else if (f.severity === "HIGH") penalty += 16;
    else if (f.severity === "MEDIUM") penalty += 8;
    else if (f.severity === "LOW") penalty += 3;
  }
  const score = Math.max(0, 100 - penalty);
  const grade = score >= 90 ? "A" : score >= 80 ? "B" : score >= 65 ? "C" : score >= 50 ? "D" : "F";
  return { score, grade };
}

export async function auditSolanaAddress(address, opts = {}) {
  const rpcs = opts.rpcs || DEFAULT_RPCS;
  const startedAt = Date.now();
  const findings = [];
  const { result: acctResp, rpcUsed } = await solanaRpc(
    "getAccountInfo",
    [address, { encoding: "jsonParsed", commitment: "confirmed" }],
    rpcs
  );
  const slot = acctResp?.context?.slot || null;
  const value = acctResp?.value;

  if (!value) {
    findings.push({
      id: "SOL-ACCT-001",
      severity: "HIGH",
      title: "Account Not Initialized on Solana Mainnet",
      detail: `Address ${address} holds 0 lamports and has no initialized state at slot ${slot}. Any SPL transfer or CPI targeting this account without createIdempotent will fail.`,
      remediation: "Fund the account above rent-exempt minimum or initialize Associated Token Accounts via createAssociatedTokenAccountIdempotent."
    });
    return {
      target: address,
      kind: "uninitialized_account",
      network: "solana-mainnet",
      rpcUsed,
      slot,
      durationMs: Date.now() - startedAt,
      ...scoreFindings(findings),
      summary: { exists: false, lamports: 0 },
      findings
    };
  }

  const owner = value.owner;
  const lamports = value.lamports;
  const parsed = value.data?.parsed;

  // Case 1: SPL Token or SPL Token-2022 Mint
  if ((owner === PROGRAMS.SPL_TOKEN || owner === PROGRAMS.TOKEN_2022) && parsed?.type === "mint") {
    const is2022 = owner === PROGRAMS.TOKEN_2022;
    const info = parsed.info || {};
    const exts = Array.isArray(info.extensions) ? info.extensions : [];

    if (info.mintAuthority) {
      findings.push({
        id: "SOL-MINT-001",
        severity: "MEDIUM",
        title: "Active Mint Authority Retained",
        detail: `mintAuthority is active (${info.mintAuthority}). Unlimited additional token supply can be minted unless governed by an audited multisig or issuer reserve policy.`,
        remediation: "Revoke mintAuthority (`spl-token authorize <MINT> mint --disable`) for fixed-supply assets, or verify Squads v4 multisig custody."
      });
    } else {
      findings.push({
        id: "SOL-MINT-000",
        severity: "PASS",
        title: "Mint Authority Permanently Revoked",
        detail: "mintAuthority is null; token supply cannot be inflated.",
        remediation: "None required."
      });
    }

    if (info.freezeAuthority) {
      findings.push({
        id: "SOL-MINT-002",
        severity: "MEDIUM",
        title: "Active Freeze Authority Retained",
        detail: `freezeAuthority is active (${info.freezeAuthority}), allowing individual holder token accounts to be frozen.`,
        remediation: "Expected for regulated stablecoins (USDC/PYUSD); DeFi/meme tokens should revoke freezeAuthority prior to AMM pool creation."
      });
    }

    if (is2022) {
      for (const ext of exts) {
        const name = ext.extension;
        const st = ext.state || {};
        if (name === "permanentDelegate" && st.delegate) {
          findings.push({
            id: "SOL-T22-001",
            severity: "HIGH",
            title: "Token-2022 Permanent Delegate Enabled (Unconditional Seizure/Burn Capability)",
            detail: `permanentDelegate is set to ${st.delegate}. This authority can transfer or burn tokens from ANY holder's Associated Token Account without owner signature.`,
            remediation: "Disclose PermanentDelegate prominently in dApp UIs and reject unverified PermanentDelegate mints in permissionless lending/AMM vaults."
          });
        } else if (name === "transferHook" && st.programId) {
          findings.push({
            id: "SOL-T22-002",
            severity: "HIGH",
            title: "Token-2022 Custom Transfer Hook Program Attached",
            detail: `Every transfer invokes external program ${st.programId} (authority: ${st.authority || "none"}). An upgradeable hook can halt transfers or break vault withdrawals.`,
            remediation: "Audit the TransferHook program's upgradeAuthority and ensure ExtraAccountMetaList accounts are deterministic and non-DOSable."
          });
        } else if (name === "transferFeeConfig") {
          const bps = st.newerTransferFee?.transferFeeBasisPoints ?? 0;
          const auth = st.transferFeeConfigAuthority;
          findings.push({
            id: "SOL-T22-003",
            severity: bps > 0 ? "MEDIUM" : auth ? "LOW" : "PASS",
            title: `Token-2022 Transfer Fee Extension (${bps} bps active)`,
            detail: `Active fee=${bps} bps (maxFee=${st.newerTransferFee?.maximumFee ?? 0}), feeConfigAuthority=${auth || "revoked"}, withdrawWithheldAuthority=${st.withdrawWithheldAuthority || "none"}.`,
            remediation: "Vaults and routers must read post-transfer balance deltas (`amount_received`) rather than assuming 1:1 SPL transfer amounts."
          });
        } else if (name === "defaultAccountState" && st.state === "frozen") {
          findings.push({
            id: "SOL-T22-004",
            severity: "HIGH",
            title: "Token-2022 DefaultAccountState = Frozen",
            detail: "Newly created ATAs start in a FROZEN state and cannot receive or transfer tokens until thawed by freezeAuthority.",
            remediation: "Verify KYC allowlist flow before integrating this mint into automated settlement or x402 payment pipelines."
          });
        } else if (name === "mintCloseAuthority" && st.closeAuthority) {
          findings.push({
            id: "SOL-T22-005",
            severity: "LOW",
            title: "Token-2022 Mint Close Authority Present",
            detail: `closeAuthority (${st.closeAuthority}) can close the mint account if total supply reaches zero.`,
            remediation: "Ensure protocol PDAs do not assume permanent account existence if supply can reach zero."
          });
        } else if (name === "confidentialTransferMint") {
          findings.push({
            id: "SOL-T22-006",
            severity: "INFO",
            title: "Token-2022 Confidential Transfers Configured",
            detail: `autoApproveNewAccounts=${Boolean(st.autoApproveNewAccounts)}, authority=${st.authority || "none"}, auditorKey=${st.auditorElgamalPubkey ? "present" : "none"}.`,
            remediation: "Standard indexers reading plain UI amounts should handle confidential balance states gracefully."
          });
        }
      }
    }

    return {
      target: address,
      kind: is2022 ? "spl_token_2022_mint" : "spl_token_mint",
      network: "solana-mainnet",
      rpcUsed,
      slot,
      durationMs: Date.now() - startedAt,
      ...scoreFindings(findings),
      summary: {
        program: is2022 ? "Token-2022" : "SPL Token",
        decimals: info.decimals,
        supply: info.supply,
        isInitialized: info.isInitialized,
        mintAuthority: info.mintAuthority || null,
        freezeAuthority: info.freezeAuthority || null,
        extensionCount: exts.length,
        extensions: exts.map(e => e.extension)
      },
      findings
    };
  }

  // Case 2: BPF Upgradeable Program
  if (owner === PROGRAMS.BPF_UPGRADEABLE && parsed?.type === "program") {
    const programDataAddress = parsed.info?.programData;
    const { result: pdSlice } = await solanaRpc(
      "getAccountInfo",
      [programDataAddress, { encoding: "base64", dataSlice: { offset: 0, length: 45 }, commitment: "confirmed" }],
      rpcs
    );
    const header = decodeProgramDataHeader(pdSlice.value.data[0]);
    let authorityOwner = null;
    let governanceKind = "immutable";

    if (!header.immutable && header.upgradeAuthority) {
      const { result: authAcct } = await solanaRpc(
        "getAccountInfo",
        [header.upgradeAuthority, { encoding: "base64", dataSlice: { offset: 0, length: 0 }, commitment: "confirmed" }],
        rpcs
      );
      authorityOwner = authAcct?.value?.owner || PROGRAMS.SYSTEM;
      if (authorityOwner === PROGRAMS.SQUADS_V4 || authorityOwner === PROGRAMS.SQUADS_V3) {
        governanceKind = "squads_multisig_or_program";
      } else if (authorityOwner === PROGRAMS.SPL_GOVERNANCE) {
        governanceKind = "spl_governance_dao";
      } else if (authorityOwner === PROGRAMS.SYSTEM) {
        governanceKind = "system_wallet_or_squads_vault_pda";
      } else {
        governanceKind = `custom_program (${authorityOwner})`;
      }

      findings.push({
        id: "SOL-PROG-001",
        severity: authorityOwner === PROGRAMS.SYSTEM ? "MEDIUM" : "LOW",
        title: "Program Bytecode Is Upgradeable",
        detail: `ProgramData ${programDataAddress} (last deployed at slot ${header.lastDeployedSlot}) retains upgradeAuthority ${header.upgradeAuthority} (account owner: ${authorityOwner}).`,
        remediation: "Verify upgradeAuthority is a threshold Squads v4 Vault PDA with timelock + verifiable Anchor/Solana-Verify build (`solana-verify verify-from-repo`)."
      });
    } else {
      findings.push({
        id: "SOL-PROG-000",
        severity: "PASS",
        title: "Program Is Permanently Immutable",
        detail: `ProgramData ${programDataAddress} has upgradeAuthority = None (last deployed slot ${header.lastDeployedSlot}). Bytecode cannot be swapped.`,
        remediation: "None required."
      });
    }

    return {
      target: address,
      kind: "bpf_upgradeable_program",
      network: "solana-mainnet",
      rpcUsed,
      slot,
      durationMs: Date.now() - startedAt,
      ...scoreFindings(findings),
      summary: {
        executable: true,
        programDataAddress,
        lastDeployedSlot: header.lastDeployedSlot,
        immutable: header.immutable,
        upgradeAuthority: header.upgradeAuthority,
        authorityAccountOwner: authorityOwner,
        governanceKind
      },
      findings
    };
  }

  // Case 3: Wallet / Treasury / PDA — Check x402 & Solana Pay SPL USDC / PYUSD ATA Readiness
  const [{ result: usdcAtas }, { result: pyusdAtas }] = await Promise.all([
    solanaRpc("getTokenAccountsByOwner", [address, { mint: KNOWN_MINTS.USDC }, { encoding: "jsonParsed" }], rpcs),
    solanaRpc("getTokenAccountsByOwner", [address, { mint: KNOWN_MINTS.PYUSD }, { encoding: "jsonParsed" }], rpcs)
  ]);

  const hasUsdcAta = (usdcAtas?.value?.length || 0) > 0;
  const hasPyusdAta = (pyusdAtas?.value?.length || 0) > 0;
  const solBalance = lamports / 1e9;

  if (lamports < 890880) {
    findings.push({
      id: "SOL-PAY-001",
      severity: "MEDIUM",
      title: "Treasury SOL Balance Below System Rent-Exempt Threshold",
      detail: `Wallet holds ${solBalance.toFixed(9)} SOL (${lamports} lamports < 890,880 rent-exempt baseline).`,
      remediation: "Deposit >= 0.005 SOL so the wallet remains rent-exempt and can sponsor ATA creation if needed."
    });
  } else {
    findings.push({
      id: "SOL-PAY-000",
      severity: "PASS",
      title: "System Account Rent-Exempt",
      detail: `Wallet holds ${solBalance.toFixed(6)} SOL (${lamports} lamports).`,
      remediation: "None required."
    });
  }

  if (!hasUsdcAta) {
    findings.push({
      id: "SOL-PAY-002",
      severity: "HIGH",
      title: "Missing Initialized Mainnet USDC Associated Token Account (x402 / Solana Pay Failure Risk)",
      detail: `No initialized SPL USDC (${KNOWN_MINTS.USDC}) ATA found for ${address}. x402 facilitators and Solana Pay wallets sending raw TransferChecked instructions without ATA creation will revert with AccountNotInitialized.`,
      remediation: "Run `spl-token create-account EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v --owner <WALLET>` (~0.00203928 SOL rent) before advertising Solana x402 endpoints."
    });
  } else {
    const uiAmt = usdcAtas.value[0]?.account?.data?.parsed?.info?.tokenAmount?.uiAmountString || "0";
    findings.push({
      id: "SOL-PAY-003",
      severity: "PASS",
      title: "Mainnet USDC Associated Token Account Initialized",
      detail: `USDC ATA ${usdcAtas.value[0].pubkey} is initialized on-chain (balance: ${uiAmt} USDC). Ready for instant x402 & Solana Pay settlement.`,
      remediation: "None required."
    });
  }

  return {
    target: address,
    kind: "wallet_or_pda",
    network: "solana-mainnet",
    rpcUsed,
    slot,
    durationMs: Date.now() - startedAt,
    ...scoreFindings(findings),
    summary: {
      owner,
      solBalance,
      usdcAtaInitialized: hasUsdcAta,
      usdcAta: usdcAtas?.value?.[0]?.pubkey || null,
      pyusdAtaInitialized: hasPyusdAta
    },
    findings
  };
}

export async function auditSolanaUrl(rawUrl, opts = {}) {
  const startedAt = Date.now();
  const u = new URL(rawUrl.startsWith("http") ? rawUrl : `https://${rawUrl}`);
  const findings = [];
  const actionsUrl = new URL("/actions.json", u.origin).toString();

  if (u.protocol !== "https:") {
    findings.push({
      id: "SOL-BLINK-001",
      severity: "CRITICAL",
      title: "Non-HTTPS Endpoint Rejected by Solana Actions / Blinks Clients",
      detail: `URL uses ${u.protocol}. Wallet Blink unfurlers (Phantom, Backpack, Dialect) strictly enforce HTTPS.`,
      remediation: "Serve all Solana Actions, Blinks, and x402 endpoints over TLS 1.2+/1.3."
    });
  }

  // 1. Check Solana Actions / Blinks /actions.json
  let blinkDetected = false;
  try {
    const ar = await fetch(actionsUrl, {
      method: "GET",
      headers: { "Origin": "https://dial.to", "Accept": "application/json" },
      signal: AbortSignal.timeout(6000)
    });
    if (ar.ok && (ar.headers.get("content-type") || "").includes("json")) {
      const aj = await ar.json();
      if (Array.isArray(aj?.rules)) {
        blinkDetected = true;
        const acao = ar.headers.get("access-control-allow-origin");
        if (acao !== "*") {
          findings.push({
            id: "SOL-BLINK-002",
            severity: "HIGH",
            title: "Missing Access-Control-Allow-Origin: * on /actions.json",
            detail: `/actions.json returned ACAO='${acao || "missing"}'. Browser wallet extensions cannot unfurl Solana Blinks without wildcard CORS.`,
            remediation: "Add `Access-Control-Allow-Origin: *` and expose `X-Action-Version, X-Blockchain-Ids` headers on `/actions.json` and all Action API routes."
          });
        } else {
          findings.push({
            id: "SOL-BLINK-000",
            severity: "PASS",
            title: "Valid Solana Actions /actions.json Manifest & Wildcard CORS",
            detail: `Detected ${aj.rules.length} Blink routing rule(s) with ACAO: *.`,
            remediation: "None required."
          });
        }
        const openWildcard = aj.rules.find(r => r.apiPath?.includes("http") && r.pathPattern === "/**");
        if (openWildcard) {
          findings.push({
            id: "SOL-BLINK-003",
            severity: "MEDIUM",
            title: "Overly Broad /** External Proxy Rule in actions.json",
            detail: `Rule maps /** to external apiPath ${openWildcard.apiPath}, expanding Blink signing surface.`,
            remediation: "Scope pathPattern to explicit action prefixes such as `/api/actions/*`."
          });
        }
      }
    }
  } catch (_) {}

  // 2. Probe target URL for x402 Payment Required & Solana treasury ATA readiness
  let x402SolanaPayTo = null;
  let httpStatus = null;
  try {
    const r = await fetch(u.toString(), {
      method: "GET",
      headers: { "Accept": "application/json" },
      signal: AbortSignal.timeout(7000)
    });
    httpStatus = r.status;
    const hsts = r.headers.get("strict-transport-security");
    const xcto = r.headers.get("x-content-type-options");
    if (!hsts) {
      findings.push({
        id: "SOL-HTTP-001",
        severity: "LOW",
        title: "Missing Strict-Transport-Security (HSTS) Header",
        detail: `${u.origin} did not send Strict-Transport-Security.`,
        remediation: "Set `Strict-Transport-Security: max-age=63072000; includeSubDomains`."
      });
    }
    if (xcto !== "nosniff") {
      findings.push({
        id: "SOL-HTTP-002",
        severity: "LOW",
        title: "Missing X-Content-Type-Options: nosniff",
        detail: `${u.origin} did not send X-Content-Type-Options: nosniff.`,
        remediation: "Add `X-Content-Type-Options: nosniff` to prevent MIME-sniffing attacks."
      });
    }

    let payHeaderObj = null;
    const prHeader = r.headers.get("payment-required") || r.headers.get("x-payment-required");
    if (prHeader) {
      try {
        payHeaderObj = JSON.parse(Buffer.from(prHeader, "base64").toString("utf8"));
      } catch (_) {}
    }
    if (!payHeaderObj && r.status === 402) {
      try {
        payHeaderObj = await r.clone().json();
      } catch (_) {}
    }

    const accepts = payHeaderObj?.accepts || [];
    const solAccept = accepts.find(a => String(a.network || "").toLowerCase().includes("solana") || isValidSolanaAddress(a.payTo));
    if (solAccept && isValidSolanaAddress(solAccept.payTo)) {
      x402SolanaPayTo = solAccept.payTo;
      const walletAudit = await auditSolanaAddress(x402SolanaPayTo, opts);
      findings.push({
        id: "SOL-X402-001",
        severity: "PASS",
        title: "x402 Solana Payment Rail Detected",
        detail: `Endpoint advertises Solana x402 settlement to treasury ${x402SolanaPayTo}.`,
        remediation: "None required."
      });
      for (const wf of walletAudit.findings) findings.push(wf);
    } else if (!blinkDetected) {
      findings.push({
        id: "SOL-WEB-001",
        severity: "INFO",
        title: "No /actions.json Blink Manifest or 402 Solana Payment Header on Root Path",
        detail: `HTTP ${httpStatus} returned without Solana Blink rules or 402 challenge on ${u.pathname}. Pass a specific x402 API route or on-chain Mint/Program address for deeper inspection.`,
        remediation: "Publish `/actions.json` for Solana Blinks or pass an active x402 route."
      });
    }
  } catch (err) {
    findings.push({
      id: "SOL-HTTP-ERR",
      severity: "HIGH",
      title: "Endpoint Unreachable or Timed Out",
      detail: err.message,
      remediation: "Verify DNS, TLS certificate chain, and public reachability."
    });
  }

  return {
    target: u.toString(),
    kind: "solana_endpoint",
    network: "solana-mainnet",
    httpStatus,
    blinkDetected,
    x402SolanaPayTo,
    durationMs: Date.now() - startedAt,
    ...scoreFindings(findings),
    findings
  };
}

export async function scanTarget(target, opts = {}) {
  const clean = String(target || "").trim();
  if (!clean) throw new Error("Missing scan target (Solana Mint, Program ID, Wallet, or Blink/x402 URL)");
  if (isValidSolanaAddress(clean)) return auditSolanaAddress(clean, opts);
  return auditSolanaUrl(clean, opts);
}
