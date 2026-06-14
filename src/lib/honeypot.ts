// Real honey pot detection for Solana tokens, backed by the
// GoPlus Solana Token Security API. Replaces keyword-based heuristics with
// concrete on-chain security checks: sell-blocking transfer hooks, excessive
// transfer fees, default-frozen accounts, mutable mint/freeze authorities,
// closable mints, and other transfer restrictions.
//
// Docs: https://docs.gopluslabs.io/reference/get_token-security-solana

export type HoneyPotStatus =
  | "SAFE"
  | "SUSPICIOUS"
  | "HIGH RISK"
  | "CONFIRMED HONEYPOT";

export interface HoneyPotCheck {
  id: string;
  label: string;
  ok: boolean;
  severity: "info" | "warn" | "high" | "critical";
  detail: string;
}

export interface HoneyPotReport {
  status: HoneyPotStatus;
  /** Short human reasons for every failing check (UI-friendly). */
  reasons: string[];
  /** Full list of checks performed (passed + failed) for the UI. */
  checks: HoneyPotCheck[];
  /** True when we got a live response from GoPlus. */
  available: boolean;
  /** Buy / sell simulation outcomes inferred from token security data. */
  buyAllowed: boolean;
  sellAllowed: boolean;
  /** Sell tax / transfer-fee percent if applicable. */
  sellTaxPct: number | null;
  source: "goplus" | "fallback";
}

interface GoPlusAuthorityField {
  authority?: { address?: string }[] | null;
  status?: string;
}

interface GoPlusTransferFee {
  current_fee_rate?: string | number;
  maximum_fee_rate?: string | number;
  scheduled_fee_rate?: string | number;
}

interface GoPlusTokenSecurity {
  balance_mutable_authority?: GoPlusAuthorityField;
  closable?: GoPlusAuthorityField;
  default_account_state?: string; // "1" initialized, "2" frozen
  default_account_state_upgradable?: GoPlusAuthorityField;
  freezable?: GoPlusAuthorityField;
  mintable?: GoPlusAuthorityField;
  non_transferable?: string; // "1" = non-transferable token
  transfer_fee?: GoPlusTransferFee;
  transfer_fee_upgradable?: GoPlusAuthorityField;
  transfer_hook?: { address?: string }[] | null;
  transfer_hook_upgradable?: GoPlusAuthorityField;
  trusted_token?: number | string;
}

const num = (v: unknown): number => {
  if (v == null) return 0;
  const n = typeof v === "string" ? parseFloat(v) : Number(v);
  return isFinite(n) ? n : 0;
};

const flag = (v: unknown): boolean => v === "1" || v === 1 || v === true;

async function fetchGoPlus(mint: string): Promise<GoPlusTokenSecurity | null> {
  try {
    const url = `https://api.gopluslabs.io/api/v1/solana/token_security?contract_addresses=${mint}`;
    const r = await fetch(url, { headers: { accept: "application/json" } });
    if (!r.ok) return null;
    const j: any = await r.json();
    const data = j?.result?.[mint] ?? j?.result?.[mint.toLowerCase()] ?? null;
    return data && typeof data === "object" ? (data as GoPlusTokenSecurity) : null;
  } catch {
    return null;
  }
}

function statusFromChecks(checks: HoneyPotCheck[]): HoneyPotStatus {
  const failed = checks.filter((c) => !c.ok);
  if (failed.some((c) => c.severity === "critical")) return "CONFIRMED HONEYPOT";
  const highs = failed.filter((c) => c.severity === "high").length;
  if (highs >= 2) return "CONFIRMED HONEYPOT";
  if (highs === 1) return "HIGH RISK";
  if (failed.some((c) => c.severity === "warn")) return "SUSPICIOUS";
  return "SAFE";
}

/**
 * Analyze a Solana mint for honey-pot mechanics using GoPlus token security.
 * `freezeAuthorityActive` is a fallback signal from the Solana RPC so we can
 * still warn even when GoPlus is unreachable.
 */
export async function analyzeHoneyPot(
  mint: string,
  fallback: { freezeAuthorityActive: boolean; mintAuthorityActive: boolean },
): Promise<HoneyPotReport> {
  const data = await fetchGoPlus(mint);

  if (!data) {
    // Fallback: only RPC-derived signals available. We can't simulate a sell.
    const checks: HoneyPotCheck[] = [
      {
        id: "freeze",
        label: "Freeze authority revoked",
        ok: !fallback.freezeAuthorityActive,
        severity: "high",
        detail: fallback.freezeAuthorityActive
          ? "Freeze authority is active — the developer can freeze any holder, blocking sells."
          : "Freeze authority revoked.",
      },
      {
        id: "mint",
        label: "Mint authority revoked",
        ok: !fallback.mintAuthorityActive,
        severity: "warn",
        detail: fallback.mintAuthorityActive
          ? "Mint authority is active — supply can be inflated to dump on holders."
          : "Mint authority revoked.",
      },
    ];
    return {
      status: statusFromChecks(checks),
      reasons: checks.filter((c) => !c.ok).map((c) => c.detail),
      checks,
      available: false,
      buyAllowed: true,
      sellAllowed: !fallback.freezeAuthorityActive,
      sellTaxPct: null,
      source: "fallback",
    };
  }

  const checks: HoneyPotCheck[] = [];

  // 1. Sell blocked — non-transferable SPL token extension. Buys can succeed
  //    (mint to a wallet) but holders can never transfer/sell.
  const nonTransferable = flag(data.non_transferable);
  checks.push({
    id: "sell-blocked",
    label: "Sell allowed",
    ok: !nonTransferable,
    severity: "critical",
    detail: nonTransferable
      ? "Token is marked non-transferable — buys may succeed but sells are blocked at the protocol level."
      : "Token is transferable. Sells are not blocked at the protocol level.",
  });

  // 2. Default-frozen accounts — new buyers receive frozen accounts and
  //    cannot sell until the authority thaws them (whitelist-only selling).
  const defaultFrozen = data.default_account_state === "2";
  checks.push({
    id: "whitelist-only",
    label: "Open trading (no whitelist)",
    ok: !defaultFrozen,
    severity: "critical",
    detail: defaultFrozen
      ? "Default account state is FROZEN — new buyers must be whitelisted by the authority before they can sell."
      : "Token accounts are unfrozen by default — no whitelist gate detected.",
  });

  // 3. Transfer hook — custom on-chain program runs on every transfer. This
  //    is the vector for cooldowns, anti-whale limits, blacklists, and
  //    selective sell blocks.
  const hooks = Array.isArray(data.transfer_hook) ? data.transfer_hook : [];
  const hasHook = hooks.length > 0;
  checks.push({
    id: "transfer-hook",
    label: "No transfer restrictions",
    ok: !hasHook,
    severity: "high",
    detail: hasHook
      ? `Custom transfer-hook program attached (${hooks[0]?.address ?? "unknown"}). Can enforce cooldowns, anti-whale limits, blacklists, or selective sell blocks.`
      : "No transfer-hook program — transfers cannot be programmatically restricted.",
  });

  // 4. Excessive sell tax via SPL transfer-fee extension.
  const currentFee = num(data.transfer_fee?.current_fee_rate); // basis points
  const maxFee = num(data.transfer_fee?.maximum_fee_rate);
  const sellTaxPct = currentFee / 100; // bps → %
  const maxFeePct = maxFee / 100;
  const taxOk = sellTaxPct < 10;
  checks.push({
    id: "sell-tax",
    label: "Sell tax under 10%",
    ok: taxOk,
    severity: sellTaxPct >= 50 ? "critical" : sellTaxPct >= 20 ? "high" : "warn",
    detail: currentFee > 0
      ? `Transfer fee is ${sellTaxPct.toFixed(2)}% (max configurable ${maxFeePct.toFixed(2)}%). ${sellTaxPct >= 50 ? "Effectively confiscatory — close to a honey pot." : sellTaxPct >= 20 ? "Excessive — most of a sell goes to the developer." : "Above the 10% comfort threshold."}`
      : "No SPL transfer fee configured.",
  });

  // 5. Fee upgradeable — dev can raise the fee to 100% later.
  const feeUpgradeable = flag(data.transfer_fee_upgradable?.status);
  checks.push({
    id: "fee-upgradable",
    label: "Transfer fee locked",
    ok: !feeUpgradeable,
    severity: "warn",
    detail: feeUpgradeable
      ? "Transfer-fee authority is active — the developer can raise the sell tax at any time, including to 100%."
      : "Transfer-fee config is locked.",
  });

  // 6. Freeze authority — dev can freeze any wallet, blocking that holder's sell.
  const freezable = flag(data.freezable?.status);
  checks.push({
    id: "freezable",
    label: "Freeze authority revoked",
    ok: !freezable,
    severity: "high",
    detail: freezable
      ? "Freeze authority is active — the developer can freeze any holder's wallet, blocking sells on demand."
      : "Freeze authority revoked.",
  });

  // 7. Default-account-state upgradeable — dev can switch into whitelist mode.
  const defaultStateUpgradeable = flag(data.default_account_state_upgradable?.status);
  checks.push({
    id: "default-state-upgradable",
    label: "Account state config locked",
    ok: !defaultStateUpgradeable,
    severity: "warn",
    detail: defaultStateUpgradeable
      ? "Default-account-state authority is active — dev can flip token into whitelist-only mode later."
      : "Default account state cannot be changed.",
  });

  // 8. Mintable — uncapped supply lets the dev dilute holders (anti-whale-adjacent risk).
  const mintable = flag(data.mintable?.status);
  checks.push({
    id: "mintable",
    label: "Mint authority revoked",
    ok: !mintable,
    severity: "warn",
    detail: mintable
      ? "Mint authority is active — new tokens can be created at will, diluting holders."
      : "Mint authority revoked — supply is fixed.",
  });

  // 9. Closable — closing the mint can brick transfers entirely.
  const closable = flag(data.closable?.status);
  checks.push({
    id: "closable",
    label: "Mint cannot be closed",
    ok: !closable,
    severity: "high",
    detail: closable
      ? "Close-mint authority is active — dev can close the mint account, breaking all future transfers."
      : "Mint account is not closable.",
  });

  // 10. Balance mutable — extension lets an authority change individual balances.
  const balanceMutable = flag(data.balance_mutable_authority?.status);
  checks.push({
    id: "balance-mutable",
    label: "Balances immutable",
    ok: !balanceMutable,
    severity: "critical",
    detail: balanceMutable
      ? "Balance-mutable authority is active — the developer can rewrite any wallet's balance (zero out holders, anti-whale clamp)."
      : "Holder balances cannot be altered by the developer.",
  });

  // Buy is assumed allowed unless the entire token is non-transferable.
  const buyAllowed = !nonTransferable;
  const sellAllowed =
    !nonTransferable && !defaultFrozen && sellTaxPct < 99 && !balanceMutable;

  const status = statusFromChecks(checks);
  const reasons = checks.filter((c) => !c.ok).map((c) => c.detail);

  return {
    status,
    reasons,
    checks,
    available: true,
    buyAllowed,
    sellAllowed,
    sellTaxPct: currentFee > 0 ? sellTaxPct : null,
    source: "goplus",
  };
}
