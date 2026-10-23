import { ntlmType1, ntlmType3 } from "./ntlm.server";

const BASE = "https://apps.guc.edu.eg";
// Pages that list grades. Add more paths here to collect more grade types.
const GRADE_PATHS = ["/student_ext/Grade/CheckGrade_01.aspx"];

export class GucError extends Error {
  constructor(
    message: string,
    public code: "bad_credentials" | "unreachable" | "unexpected",
  ) {
    super(message);
  }
}

export type GradeRow = { course: string; item: string; grade: string };

function splitUser(raw: string): { user: string; domain: string } {
  const t = raw.trim();
  const i = t.indexOf("\\");
  return i > -1 ? { domain: t.slice(0, i), user: t.slice(i + 1) } : { domain: "", user: t };
}

async function ntlmGet(path: string, rawUser: string, password: string): Promise<string> {
  const { user, domain } = splitUser(rawUser);
  const url = BASE + path;
  let r1: Response;
  try {
    r1 = await fetch(url, {
      headers: { Authorization: `NTLM ${ntlmType1()}` },
      redirect: "manual",
    });
  } catch {
    throw new GucError("Could not reach the GUC portal.", "unreachable");
  }
  const challenge = /NTLM\s+([A-Za-z0-9+/=]+)/.exec(r1.headers.get("www-authenticate") ?? "");
  await r1.arrayBuffer().catch(() => null);
  if (!challenge) {
    throw new GucError(
      `GUC portal did not start a login handshake (status ${r1.status}).`,
      "unexpected",
    );
  }
  const r2 = await fetch(url, {
    headers: { Authorization: `NTLM ${ntlmType3(challenge[1], user, password, domain)}` },
    redirect: "manual",
  });
  if (r2.status === 401) {
    await r2.arrayBuffer().catch(() => null);
    throw new GucError("GUC rejected the username or password.", "bad_credentials");
  }
  if (!r2.ok) {
    await r2.arrayBuffer().catch(() => null);
    throw new GucError(`GUC portal returned status ${r2.status}.`, "unexpected");
  }
  return r2.text();
}

const decode = (s: string) =>
  s
    .replace(/<[^>]*>/g, " ")
    .replace(/&nbsp;/gi, " ")
    .replace(/&amp;/gi, "&")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/&quot;/gi, '"')
    .replace(/&#39;/g, "'")
    .replace(/&#(\d+);/g, (_, n) => String.fromCharCode(Number(n)))
    .replace(/\s+/g, " ")
    .trim();

/** Best-effort parser: reads every innermost HTML table and turns rows into grade entries. */
export function parseGrades(html: string): GradeRow[] {
  const tables = [...html.matchAll(/<table\b((?:(?!<table\b)[\s\S])*?)<\/table>/gi)].map((m) => m[1]);
  const preferred = tables.filter((t) => /id="[^"]*(midDg|grade|Dg)[^"]*"/i.test(t.split(">")[0]));
  const chosen = preferred.length ? preferred : tables;
  const rows: GradeRow[] = [];
  const seen = new Map<string, number>();
  for (const t of chosen) {
    for (const tr of t.matchAll(/<tr\b[\s\S]*?<\/tr>/gi)) {
      const cells = [...tr[0].matchAll(/<td\b[\s\S]*?<\/td>/gi)].map((c) => decode(c[0]));
      if (cells.length < 2 || cells.every((c) => !c)) continue;
      let course = "General";
      let item: string;
      let grade: string;
      if (cells.length >= 3) {
        course = cells[0] || course;
        item = cells.slice(1, -1).filter(Boolean).join(" – ") || "Grade";
        grade = cells[cells.length - 1];
      } else {
        item = cells[0];
        grade = cells[1];
      }
      if (!grade) continue;
      const key = `${course}|${item}`;
      const n = seen.get(key) ?? 0;
      seen.set(key, n + 1);
      rows.push({ course, item: n ? `${item} (${n + 1})` : item, grade });
    }
  }
  return rows;
}

export async function fetchGrades(username: string, password: string): Promise<GradeRow[]> {
  const all: GradeRow[] = [];
  for (const p of GRADE_PATHS) {
    all.push(...parseGrades(await ntlmGet(p, username, password)));
  }
  return all;
}
