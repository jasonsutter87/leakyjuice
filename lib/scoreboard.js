// lib/scoreboard.js — the CTF scoreboard. Deliberately hackable (v12): the instrument
// that grades you is itself a target. The joke's punchline is verify(): the server has
// been quietly recording which flags it ACTUALLY emitted to each player, so an honest
// recompute exposes any forged/tampered score. Lesson: trust server-verified captures,
// never the self-reported claim — the werbos honest-abstain thesis, applied to scoring.
import { FLAGS } from './db.js';

// player -> Set(flags the server truly emitted to them)   ← the source of truth
const EARNED = new Map();
// player -> { name, score, claimed:Set(flags), updated }   ← the writable (hackable) board
const CLAIMED = new Map();

export function resetScores() { EARNED.clear(); CLAIMED.clear(); }

// Called by the response middleware: record every FLAG the server hands this player.
export function observe(player, body) {
  if (!player || typeof body !== 'string') return;
  const set = EARNED.get(player) || new Set();
  const re = /FLAG\{lj_[a-z0-9_]+\}/g; let m;
  while ((m = re.exec(body))) set.add(m[0]);
  if (set.size) EARNED.set(player, set);
}
function board(player) {
  if (!CLAIMED.has(player)) CLAIMED.set(player, { name: player, score: 0, claimed: new Set(), updated: Date.now() });
  return CLAIMED.get(player);
}

// The TOTAL number of gradeable flags (for the "100%" gag).
const TOTAL = Object.keys(FLAGS).filter((k) => FLAGS[k]).length;

// VULN: trusts a client-supplied score with no recompute.
export function setScore({ player, name, score }) {
  const b = board(player);
  if (name != null) b.name = name;          // rendered raw on /leaderboard → stored XSS
  b.score = Number(score);                  // whatever you say
  b.updated = Date.now();
  return { ok: true, player, score: b.score, flag: FLAGS.scoreboard_score_tamper };
}

// VULN: records a claimed flag with NO proof the player earned it.
export function claimFlag({ player, name, flag, actor }) {
  const b = board(player);
  if (name != null) b.name = name;
  const out = { ok: true, player, flags: [] };
  const flags = new Set();
  if (flag) {
    b.claimed.add(flag);
    b.score = Math.max(Number(b.score) || 0, b.claimed.size); // don't clobber a tampered score
    // forgery: the claimed flag was never actually emitted to this player by the server
    const earned = EARNED.get(player) || new Set();
    if (!earned.has(flag)) flags.add(FLAGS.scoreboard_flag_forgery);
  }
  if (name && /[<>]/.test(name)) flags.add(FLAGS.scoreboard_xss);   // markup in the name
  if (actor && actor !== player) flags.add(FLAGS.scoreboard_idor);   // wrote someone else's row
  out.flags = [...flags];
  return out;
}

export function leaderboard() {
  return [...CLAIMED.values()].map((b) => ({ name: b.name, score: b.score })).sort((a, b) => b.score - a.score);
}
export function leaderboardRaw() { return [...CLAIMED.values()]; } // for the HTML page (renders name raw)

// The punchline: honest recompute from what the server actually emitted.
export function verify(player) {
  const b = CLAIMED.get(player) || { score: 0, claimed: new Set() };
  const earned = EARNED.get(player) || new Set();
  const claimed = [...b.claimed];
  const forged = claimed.filter((f) => !earned.has(f));
  const honest = forged.length === 0 && b.score <= earned.size;
  const out = {
    player, total: TOTAL,
    claimed_score: b.score, claimed_flags: claimed.length,
    verified_flags: earned.size, forged_flags: forged.length, forged,
    honest,
    verdict: honest
      ? `verified ${earned.size}/${TOTAL} — clean.`
      : `claimed ${Math.max(b.score, claimed.length)}, verified ${earned.size}. ${Math.max(b.score, claimed.length) - earned.size} forged. A writable scoreboard is worthless.`
  };
  // god-mode gag: fraudulently at/over 100% but the server didn't emit them
  if ((b.score >= TOTAL || claimed.length >= TOTAL) && earned.size < TOTAL) out.flag = FLAGS.scoreboard_pwned;
  return out;
}
