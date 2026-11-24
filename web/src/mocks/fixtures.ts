/**
 * Deterministic, internally consistent demo data for the mock API.
 * Times are relative to the moment the module loads so the UI always looks "live".
 */
import type {
  AuditEntry,
  AuthProfile,
  BumpType,
  Finding,
  FindingStatus,
  Job,
  JobEvent,
  NotifierStatus,
  RepoRecord,
  RuntimeStatus,
  ScanRun,
  Severity,
  SourceStatus,
  Suppression,
  Target,
} from "@/api/types";

export const NOW = Date.now();
const H = 3600_000;
const D = 24 * H;
export const iso = (ms: number) => new Date(ms).toISOString();
const ago = (ms: number) => iso(NOW - ms);

/** 64-bit-ish FNV-1a, hex. Stable ids for fixtures. */
export function hashId(s: string): string {
  let h1 = 0x811c9dc5;
  let h2 = 0x01000193;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    h1 = Math.imul(h1 ^ c, 0x01000193) >>> 0;
    h2 = Math.imul(h2 ^ c, 0x0100019d) >>> 0;
  }
  return h1.toString(16).padStart(8, "0") + h2.toString(16).padStart(8, "0");
}

/** Deterministic 0..1 from a string. */
function rand(s: string) {
  return parseInt(hashId(s).slice(0, 6), 16) / 0xffffff;
}

export const ACTOR = "alice@acme.example";

// ---- auth profiles & targets -------------------------------------------------

export function makeAuthProfiles(): AuthProfile[] {
  return [
    {
      id: 1,
      name: "github-token",
      type: "token",
      options: {},
      has_secret: true,
      secret_fingerprint: "1a2b3c4d…k9Qz",
      origin: "config",
      created_at: ago(120 * D),
      updated_at: ago(30 * D),
    },
    {
      id: 2,
      name: "globex-app",
      type: "app",
      options: { app_id: 412233, installation_id: 50918822 },
      has_secret: true,
      secret_fingerprint: "9f8e7d6c…AB12",
      origin: "ui",
      created_at: ago(60 * D),
      updated_at: ago(12 * D),
    },
    {
      id: 3,
      name: "deploy-ssh",
      type: "ssh",
      options: { known_hosts: "github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl" },
      has_secret: true,
      secret_fingerprint: "77aa01ce…x0Pm",
      origin: "ui",
      created_at: ago(45 * D),
      updated_at: ago(45 * D),
    },
    {
      id: 4,
      name: "spare-token",
      type: "token",
      options: {},
      has_secret: false,
      origin: "ui",
      created_at: ago(5 * D),
      updated_at: ago(5 * D),
    },
  ];
}

export function makeTargets(): Target[] {
  const base = { provider: "github", branch: "", repos: [] as string[] };
  return [
    {
      ...base,
      id: 1,
      kind: "org",
      owner: "acme",
      auth: "github-token",
      filter: { skip_archived: true, skip_forks: true, skip_empty: true, exclude: ["acme/sandbox-*"] },
      schedule: "0 2 * * *",
      enabled: true,
      label: "org:acme",
      origin: "config",
      next_run_at: iso(Math.ceil(NOW / D) * D + 2 * H),
      created_at: ago(120 * D),
      updated_at: ago(30 * D),
    },
    {
      ...base,
      id: 2,
      kind: "org",
      owner: "globex",
      auth: "globex-app",
      filter: { skip_archived: true, skip_forks: true, skip_empty: true, topics: ["production"] },
      schedule: "0 2 */3 * *",
      enabled: true,
      label: "org:globex",
      origin: "ui",
      next_run_at: iso(Math.ceil(NOW / D) * D + 2 * D + 2 * H),
      created_at: ago(60 * D),
      updated_at: ago(12 * D),
    },
    {
      ...base,
      id: 3,
      kind: "user",
      owner: "jdoe",
      auth: "github-token",
      filter: { skip_archived: true, skip_forks: false, skip_empty: true },
      schedule: "",
      enabled: false,
      label: "user:jdoe",
      origin: "ui",
      next_run_at: null,
      created_at: ago(20 * D),
      updated_at: ago(3 * D),
    },
    {
      ...base,
      id: 4,
      kind: "repo",
      url: "git@github.com:acme/legacy-billing.git",
      owner: "acme",
      name: "legacy-billing",
      branch: "release/2.x",
      auth: "deploy-ssh",
      schedule: "0 2 * * *",
      enabled: true,
      label: "repo:acme/legacy-billing",
      origin: "ui",
      next_run_at: iso(Math.ceil(NOW / D) * D + 2 * H),
      created_at: ago(45 * D),
      updated_at: ago(45 * D),
    },
  ];
}

// ---- repos -------------------------------------------------------------------

type Eco = "go" | "npm" | "pypi" | "maven" | "none";
interface RepoSeed {
  full: string;
  target: number;
  eco: Eco;
  manifest: string;
  topics?: string[];
  privateRepo?: boolean;
  branch?: string;
}

export const REPO_SEEDS: RepoSeed[] = [
  { full: "acme/api", target: 1, eco: "go", manifest: "go.mod", topics: ["backend", "production"] },
  { full: "acme/payments", target: 1, eco: "go", manifest: "go.mod", topics: ["pci", "production"] },
  { full: "acme/web", target: 1, eco: "npm", manifest: "package-lock.json", topics: ["frontend"] },
  { full: "acme/mobile-bff", target: 1, eco: "npm", manifest: "package-lock.json" },
  { full: "acme/data-pipeline", target: 1, eco: "pypi", manifest: "requirements.txt", topics: ["data"] },
  { full: "acme/infra-tools", target: 1, eco: "pypi", manifest: "poetry.lock" },
  { full: "acme/legacy-billing", target: 4, eco: "maven", manifest: "pom.xml", branch: "release/2.x" },
  { full: "globex/storefront", target: 2, eco: "npm", manifest: "pnpm-lock.yaml", topics: ["production"] },
  { full: "globex/inventory", target: 2, eco: "go", manifest: "go.mod", topics: ["production"] },
  { full: "globex/auth-service", target: 2, eco: "go", manifest: "go.mod", topics: ["production", "security"] },
  { full: "globex/ml-models", target: 2, eco: "pypi", manifest: "requirements.txt", topics: ["production"] },
  { full: "jdoe/side-project", target: 3, eco: "npm", manifest: "package-lock.json", privateRepo: false },
  { full: "jdoe/dotfiles", target: 3, eco: "none", manifest: "" },
];

// ---- vulnerability catalogue ---------------------------------------------------

interface Vuln {
  eco: Exclude<Eco, "none">;
  pkg: string;
  version: string;
  advisory: string;
  aliases: string[];
  summary: string;
  severity: Severity;
  cvss?: [number, string];
  epss?: [number, number];
  kev?: boolean;
  malicious?: boolean;
  fixed: string[];
  recommended: string;
  bump: BumpType;
  direct?: boolean;
  verified?: boolean;
  sources?: string[];
}

const V = (v: Vuln) => v;

const CATALOGUE: Vuln[] = [
  V({ eco: "go", pkg: "golang.org/x/net", version: "v0.15.0", advisory: "GO-2023-2102", aliases: ["CVE-2023-44487", "CVE-2023-39325", "GHSA-4374-p667-p6c8"], summary: "HTTP/2 rapid reset can cause excessive work in net/http", severity: "HIGH", cvss: [7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"], epss: [0.944, 0.999], kev: true, fixed: ["v0.17.0"], recommended: "v0.17.0", bump: "minor" }),
  V({ eco: "go", pkg: "golang.org/x/crypto", version: "v0.14.0", advisory: "GO-2024-3321", aliases: ["CVE-2024-45337", "GHSA-v778-237x-gjrc"], summary: "Misuse of ServerConfig.PublicKeyCallback may cause authorization bypass", severity: "CRITICAL", cvss: [9.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"], epss: [0.012, 0.79], fixed: ["v0.31.0"], recommended: "v0.31.0", bump: "minor" }),
  V({ eco: "go", pkg: "golang.org/x/crypto", version: "v0.14.0", advisory: "GO-2023-2402", aliases: ["CVE-2023-48795", "GHSA-45x7-px36-x8w8"], summary: "Man-in-the-middle attacker can compromise integrity of secure channel (Terrapin)", severity: "MEDIUM", cvss: [5.9, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N"], epss: [0.63, 0.98], fixed: ["v0.17.0"], recommended: "v0.31.0", bump: "minor" }),
  V({ eco: "go", pkg: "google.golang.org/grpc", version: "v1.56.2", advisory: "GHSA-m425-mq94-257g", aliases: ["CVE-2023-44487"], summary: "gRPC-Go HTTP/2 Rapid Reset vulnerability", severity: "HIGH", cvss: [7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"], epss: [0.944, 0.999], kev: true, fixed: ["v1.56.3"], recommended: "v1.56.3", bump: "patch" }),
  V({ eco: "go", pkg: "github.com/golang-jwt/jwt/v4", version: "v4.4.2", advisory: "GHSA-29wx-vh33-7x7r", aliases: ["CVE-2024-51744", "GO-2024-3250"], summary: "Bad documentation of error handling in ParseWithClaims can lead to potentially dangerous situations", severity: "LOW", cvss: [3.1, "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"], epss: [0.0004, 0.11], fixed: ["v4.5.1"], recommended: "v4.5.1", bump: "minor" }),
  V({ eco: "go", pkg: "github.com/docker/docker", version: "v20.10.7+incompatible", advisory: "GHSA-v23v-6jw2-98fq", aliases: ["CVE-2024-41110", "GO-2024-3005"], summary: "Authz zero length regression allows AuthZ plugin bypass", severity: "CRITICAL", cvss: [10, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"], epss: [0.004, 0.71], fixed: ["v25.0.6+incompatible"], recommended: "v25.0.6+incompatible", bump: "major", direct: false }),
  V({ eco: "go", pkg: "github.com/acme/internal-sdk", version: "v1.8.0", advisory: "HEIMDALL-AI-2026-0007", aliases: [], summary: "Possible SSRF: HTTP client follows redirects to link-local addresses (reported by code review agent)", severity: "MEDIUM", fixed: [], recommended: "", bump: "no-fix-available", verified: false, sources: ["ai-agent"] }),
  V({ eco: "npm", pkg: "lodash", version: "4.17.15", advisory: "GHSA-p6mc-m468-83gw", aliases: ["CVE-2020-8203"], summary: "Prototype pollution in lodash zipObjectDeep", severity: "HIGH", cvss: [7.4, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H"], epss: [0.023, 0.84], fixed: ["4.17.19"], recommended: "4.17.21", bump: "patch", direct: false }),
  V({ eco: "npm", pkg: "axios", version: "0.21.1", advisory: "GHSA-cph5-m8f7-6c5x", aliases: ["CVE-2021-3749"], summary: "Inefficient regular expression complexity in axios", severity: "HIGH", cvss: [7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"], epss: [0.012, 0.78], fixed: ["0.21.2"], recommended: "1.7.4", bump: "major" }),
  V({ eco: "npm", pkg: "axios", version: "0.21.1", advisory: "GHSA-wf5p-g6vw-rhxx", aliases: ["CVE-2023-45857"], summary: "Axios Cross-Site Request Forgery vulnerability (XSRF-TOKEN leak)", severity: "MEDIUM", cvss: [6.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N"], epss: [0.001, 0.4], fixed: ["1.6.0"], recommended: "1.7.4", bump: "major" }),
  V({ eco: "npm", pkg: "next", version: "13.4.0", advisory: "GHSA-f82v-jwr5-mffw", aliases: ["CVE-2025-29927"], summary: "Authorization bypass in Next.js middleware", severity: "CRITICAL", cvss: [9.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"], epss: [0.92, 0.997], fixed: ["13.5.9"], recommended: "13.5.9", bump: "minor" }),
  V({ eco: "npm", pkg: "semver", version: "5.7.1", advisory: "GHSA-c2qf-rxjj-qqgw", aliases: ["CVE-2022-25883"], summary: "semver vulnerable to Regular Expression Denial of Service", severity: "HIGH", cvss: [7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"], epss: [0.003, 0.68], fixed: ["5.7.2"], recommended: "5.7.2", bump: "patch", direct: false }),
  V({ eco: "npm", pkg: "ws", version: "7.4.5", advisory: "GHSA-3h5v-q93c-6h6q", aliases: ["CVE-2024-37890"], summary: "ws affected by a DoS when handling a request with many HTTP headers", severity: "HIGH", cvss: [7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"], epss: [0.02, 0.83], fixed: ["7.5.10"], recommended: "7.5.10", bump: "minor", direct: false }),
  V({ eco: "npm", pkg: "ua-parser-js", version: "0.7.29", advisory: "GHSA-pjwm-rvh2-c87w", aliases: ["MAL-2021-1"], summary: "Embedded malware in ua-parser-js (compromised release)", severity: "CRITICAL", malicious: true, fixed: ["0.7.30"], recommended: "0.7.30", bump: "patch", direct: false }),
  V({ eco: "npm", pkg: "event-stream", version: "3.3.6", advisory: "GHSA-mh6f-8j2x-4483", aliases: ["MAL-2018-1"], summary: "Critical severity vulnerability: malicious flatmap-stream dependency", severity: "CRITICAL", malicious: true, fixed: [], recommended: "", bump: "no-fix-available", direct: false }),
  V({ eco: "pypi", pkg: "requests", version: "2.25.1", advisory: "GHSA-j8r2-6x86-q33q", aliases: ["CVE-2023-32681", "PYSEC-2023-74"], summary: "Unintended leak of Proxy-Authorization header in requests", severity: "MEDIUM", cvss: [6.1, "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:N/A:N"], epss: [0.06, 0.92], fixed: ["2.31.0"], recommended: "2.32.3", bump: "minor" }),
  V({ eco: "pypi", pkg: "jinja2", version: "2.11.2", advisory: "GHSA-h5c8-rqwp-cp95", aliases: ["CVE-2024-22195"], summary: "Jinja vulnerable to HTML attribute injection when passing user input as keys to xmlattr filter", severity: "MEDIUM", cvss: [5.4, "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:N"], epss: [0.001, 0.35], fixed: ["3.1.3"], recommended: "3.1.4", bump: "major" }),
  V({ eco: "pypi", pkg: "pyyaml", version: "5.3", advisory: "GHSA-8q59-q68h-6hv4", aliases: ["CVE-2020-14343", "PYSEC-2021-142"], summary: "Improper input validation in PyYAML: arbitrary code execution via full_load", severity: "CRITICAL", cvss: [9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"], epss: [0.07, 0.93], fixed: ["5.4"], recommended: "6.0.2", bump: "major" }),
  V({ eco: "pypi", pkg: "urllib3", version: "1.26.4", advisory: "GHSA-v845-jxx5-vc9f", aliases: ["CVE-2023-43804"], summary: "Cookie HTTP header isn't stripped on cross-origin redirects", severity: "HIGH", cvss: [8.1, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"], epss: [0.004, 0.71], fixed: ["1.26.17"], recommended: "1.26.20", bump: "patch", direct: false }),
  V({ eco: "maven", pkg: "org.apache.logging.log4j:log4j-core", version: "2.14.1", advisory: "GHSA-jfh8-c2jp-5v3q", aliases: ["CVE-2021-44228"], summary: "Remote code injection in Log4j (Log4Shell)", severity: "CRITICAL", cvss: [10, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"], epss: [0.944, 1], kev: true, fixed: ["2.15.0", "2.12.2"], recommended: "2.17.1", bump: "minor" }),
  V({ eco: "maven", pkg: "org.springframework:spring-beans", version: "5.3.17", advisory: "GHSA-36p3-wjmg-h94x", aliases: ["CVE-2022-22965"], summary: "Remote code execution in Spring Framework (Spring4Shell)", severity: "CRITICAL", cvss: [9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"], epss: [0.943, 0.999], kev: true, fixed: ["5.3.18"], recommended: "5.3.18", bump: "patch" }),
  V({ eco: "maven", pkg: "com.fasterxml.jackson.core:jackson-databind", version: "2.9.8", advisory: "GHSA-57j2-w4cx-62h2", aliases: ["CVE-2020-36518"], summary: "Deeply nested json in jackson-databind", severity: "HIGH", cvss: [7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"], epss: [0.005, 0.73], fixed: ["2.12.6.1"], recommended: "2.12.7.1", bump: "minor", direct: false }),
];

const ECO_PURL: Record<Exclude<Eco, "none">, string> = { go: "golang", npm: "npm", pypi: "pypi", maven: "maven" };
const ECO_NAME: Record<Exclude<Eco, "none">, string> = { go: "go", npm: "npm", pypi: "PyPI", maven: "Maven" };

function purl(eco: Exclude<Eco, "none">, name: string, version: string) {
  const n = eco === "maven" ? name.replace(":", "/") : name;
  return `pkg:${ECO_PURL[eco]}/${n}@${version.replace(/^v/, eco === "go" ? "v" : "")}`;
}

function adviceFor(eco: Exclude<Eco, "none">, name: string, version: string) {
  if (!version) return "";
  switch (eco) {
    case "go":
      return `go get ${name}@${version}`;
    case "npm":
      return `npm install ${name}@${version}`;
    case "pypi":
      return `pip install '${name}>=${version}'`;
    case "maven":
      return `Set <version>${version}</version> for ${name} in pom.xml`;
  }
}

// ---- runtimes ---------------------------------------------------------------------

const RUNTIMES: Record<string, RuntimeStatus[]> = {
  "acme/api": [{ name: "go", version: "1.21.5", origin: "go.mod", via: "go directive", cycle: "1.21", status: "eol", eol_date: "2024-08-13", latest_patch: "1.21.13", latest_cycle: "1.27" }],
  "acme/payments": [
    { name: "go", version: "1.26.2", origin: "go.mod", via: "go directive", cycle: "1.26", status: "supported", eol_date: null, latest_patch: "1.26.4", latest_cycle: "1.27" },
    { name: "alpine", version: "3.18", origin: "Dockerfile", via: "Dockerfile FROM", cycle: "3.18", status: "eol", eol_date: "2025-05-09", latest_patch: "3.18.12", latest_cycle: "3.22" },
  ],
  "acme/web": [{ name: "nodejs", version: "18.19.0", origin: ".nvmrc", via: ".nvmrc", cycle: "18", status: "eol", eol_date: "2025-04-30", latest_patch: "18.20.8", latest_cycle: "24" }],
  "acme/mobile-bff": [{ name: "nodejs", version: "22.11.0", origin: "package.json", via: "engines.node", cycle: "22", status: "security-only", eol_date: "2027-04-30", latest_patch: "22.21.1", latest_cycle: "24" }],
  "acme/data-pipeline": [{ name: "python", version: "3.8.18", origin: "Dockerfile", via: "Dockerfile FROM", cycle: "3.8", status: "eol", eol_date: "2024-10-07", latest_patch: "3.8.20", latest_cycle: "3.14" }],
  "acme/infra-tools": [{ name: "python", version: "3.10.14", origin: ".python-version", via: ".python-version", cycle: "3.10", status: "eol-soon", eol_date: "2026-12-31", latest_patch: "3.10.19", latest_cycle: "3.14" }],
  "acme/legacy-billing": [{ name: "java", version: "11.0.20", origin: "pom.xml", via: "maven.compiler.release", cycle: "11", status: "security-only", eol_date: "2027-10-31", latest_patch: "11.0.29", latest_cycle: "25" }],
  "globex/storefront": [{ name: "nodejs", version: "24.4.0", origin: ".nvmrc", via: ".nvmrc", cycle: "24", status: "supported", eol_date: "2028-04-30", latest_patch: "24.11.0", latest_cycle: "24" }],
  "globex/inventory": [{ name: "go", version: "1.25.1", origin: "go.mod", via: "go directive", cycle: "1.25", status: "eol-soon", eol_date: "2027-02-11", latest_patch: "1.25.9", latest_cycle: "1.27" }],
  "globex/auth-service": [{ name: "go", version: "1.27.0", origin: "go.mod", via: "go directive", cycle: "1.27", status: "supported", eol_date: null, latest_patch: "1.27.1", latest_cycle: "1.27" }],
  "globex/ml-models": [{ name: "python", version: "3.12.4", origin: "pyproject.toml", via: "requires-python", cycle: "3.12", status: "supported", eol_date: "2028-10-31", latest_patch: "3.12.12", latest_cycle: "3.14" }],
  "jdoe/side-project": [{ name: "nodejs", version: "16.20.2", origin: "package.json", via: "engines.node", cycle: "16", status: "eol", eol_date: "2023-09-11", latest_patch: "16.20.2", latest_cycle: "24" }],
  "jdoe/dotfiles": [],
};

export function runtimesFor(repo: string): RuntimeStatus[] {
  return RUNTIMES[repo] ?? [];
}

// ---- findings ---------------------------------------------------------------------

export interface FindingRow extends Finding {
  suppression?: Suppression;
}

const SEV_RANK: Record<Severity, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, UNKNOWN: 0 };

function priority(f: Pick<Finding, "severity" | "in_kev" | "malicious" | "epss" | "direct">) {
  let p = SEV_RANK[f.severity] * 20;
  if (f.in_kev) p += 30;
  if (f.malicious) p += 40;
  p += (f.epss ?? 0) * 10;
  if (f.direct) p += 5;
  return Math.round(p * 10) / 10;
}

export function makeFindings(): FindingRow[] {
  const out: FindingRow[] = [];
  for (const repo of REPO_SEEDS) {
    if (repo.eco === "none") continue;
    const eco = repo.eco;
    for (const v of CATALOGUE.filter((c) => c.eco === eco)) {
      const key = `${repo.full}|${v.pkg}|${v.advisory}`;
      const r = rand(key);
      // Not every repo has every vulnerable package.
      if (r < 0.28 && !v.kev && !v.malicious) continue;
      if (v.malicious && !["acme/web", "globex/storefront"].includes(repo.full)) continue;
      if (v.verified === false && repo.full !== "acme/api") continue;
      const firstSeen = NOW - Math.floor(rand(`${key}|fs`) * 40 * D) - 2 * H;
      let status: FindingStatus = "open";
      if (r > 0.9) status = "fixed";
      const direct = v.direct ?? true;
      const lastSeen = status === "fixed" ? NOW - Math.floor(rand(`${key}|ls`) * 10 * D) - D : NOW - 4 * H;
      const f: FindingRow = {
        id: hashId(key),
        kind: "dependency",
        repo: repo.full,
        manifest_path: repo.manifest,
        package: { ecosystem: ECO_NAME[eco], name: v.pkg, version: v.version, purl: purl(eco, v.pkg, v.version) },
        direct,
        scope: "prod",
        parents: direct ? [] : [eco === "go" ? "github.com/acme/platform-kit@v2.3.1" : eco === "npm" ? "webpack-dev-server@3.11.2" : "boto3@1.17.0"],
        advisory_id: v.advisory,
        aliases: v.aliases,
        summary: v.summary,
        severity: v.severity,
        cvss_score: v.cvss?.[0],
        cvss_vector: v.cvss?.[1],
        epss: v.epss?.[0],
        epss_percentile: v.epss?.[1],
        in_kev: v.kev ?? false,
        malicious: v.malicious ?? false,
        verified: v.verified ?? true,
        references: [
          ...v.aliases.filter((a) => a.startsWith("CVE-")).map((a) => `https://nvd.nist.gov/vuln/detail/${a}`),
          v.advisory.startsWith("GHSA-") ? `https://github.com/advisories/${v.advisory}` : `https://osv.dev/vulnerability/${v.advisory}`,
        ],
        fixed_versions: v.fixed,
        recommended_version: v.recommended || undefined,
        bump: v.bump,
        advice: adviceFor(eco, v.pkg, v.recommended),
        sources: v.sources ?? (v.kev ? ["osv", "ghsa", "kev", "epss"] : ["osv", "ghsa", "epss"]),
        first_seen: iso(firstSeen),
        last_seen: iso(lastSeen),
        status,
      };
      f.priority = priority(f);
      out.push(f);
    }
    // Runtime findings for EOL / EOL-soon runtimes.
    for (const rt of runtimesFor(repo.full)) {
      if (rt.status !== "eol" && rt.status !== "eol-soon") continue;
      const key = `${repo.full}|runtime|${rt.name}`;
      const f: FindingRow = {
        id: hashId(key),
        kind: "runtime",
        repo: repo.full,
        manifest_path: rt.origin,
        advisory_id: `EOL-${rt.name}-${rt.cycle}`,
        aliases: [],
        summary:
          rt.status === "eol"
            ? `${rt.name} ${rt.cycle} reached end of life on ${rt.eol_date}; no more security fixes`
            : `${rt.name} ${rt.cycle} reaches end of life on ${rt.eol_date}`,
        severity: rt.status === "eol" ? "HIGH" : "MEDIUM",
        in_kev: false,
        malicious: false,
        verified: true,
        references: [`https://endoflife.date/${rt.name}`],
        fixed_versions: [],
        recommended_version: rt.latest_cycle,
        bump: "major",
        advice: `Upgrade ${rt.name} to ${rt.latest_cycle} (declared in ${rt.origin})`,
        runtime: rt,
        sources: ["endoflife"],
        first_seen: iso(NOW - Math.floor(rand(`${key}|fs`) * 60 * D) - D),
        last_seen: iso(NOW - 4 * H),
        status: "open",
      };
      f.priority = priority(f);
      out.push(f);
    }
  }
  // One suppressed finding with an active suppression.
  const sup = out.find((f) => f.repo === "acme/infra-tools" && f.package?.name === "urllib3") ?? out.find((f) => f.severity === "HIGH" && f.status === "open");
  if (sup) {
    sup.status = "suppressed";
    sup.suppression = {
      reason: "Only used by an offline CLI that never follows redirects; tracked in SEC-412.",
      expires_at: iso(NOW + 60 * D),
      actor: "bob@acme.example",
      created_at: iso(NOW - 10 * D),
    };
  }
  return out;
}

export function repoRecords(): RepoRecord[] {
  return REPO_SEEDS.map((s, i) => {
    const [owner, name] = s.full.split("/") as [string, string];
    return {
      provider: "github",
      host: "github.com",
      owner,
      name,
      full_name: s.full,
      html_url: `https://github.com/${s.full}`,
      default_branch: s.branch ?? "main",
      ref: s.branch ?? "main",
      private: s.privateRepo ?? true,
      archived: false,
      fork: false,
      topics: s.topics ?? [],
      target_id: s.target,
      last_listed_at: iso(NOW - 5 * H),
      last_head_sha: hashId(`${s.full}|sha`) + hashId(`${s.full}|sha2`).slice(0, 8) + hashId(`${s.full}|sha3`).slice(0, 16),
      last_scanned_at: s.target === 3 ? iso(NOW - 3 * D) : iso(NOW - 4 * H - i * 60_000),
      open_by_severity: {},
    };
  });
}

// ---- runs, jobs, events -------------------------------------------------------------

export function makeRuns(): ScanRun[] {
  const runs: ScanRun[] = [];
  const count = 21;
  for (let i = 0; i < count; i++) {
    const daysAgo = count - 1 - i;
    const start = Math.floor((NOW - daysAgo * D) / D) * D + 2 * H;
    const startMs = start > NOW ? start - D : start;
    const failed = i === 6;
    const partial = i === 12 || i === 17;
    const decay = (count - i) * 1.2;
    runs.push({
      id: 100 + i,
      started_at: iso(startMs),
      finished_at: iso(startMs + (6 + Math.floor(rand(`run${i}`) * 9)) * 60_000),
      status: failed ? "failed" : partial ? "partial" : "succeeded",
      targets: ["org:acme", "org:globex", "repo:acme/legacy-billing"],
      repos_scanned: failed ? [] : REPO_SEEDS.filter((r) => r.target !== 3).map((r) => r.full),
      repos_failed: partial ? ["globex/ml-models"] : [],
      sources: [
        { name: "osv", healthy: true, calls: 412, duration_ms: 8123 },
        { name: "ghsa", healthy: true, calls: 96, duration_ms: 3310 },
        { name: "nvd", healthy: !partial, error: partial ? "429 Too Many Requests" : undefined, calls: 58, duration_ms: 21004 },
        { name: "kev", healthy: true, calls: 1, duration_ms: 240 },
        { name: "epss", healthy: true, calls: 3, duration_ms: 701 },
        { name: "endoflife", healthy: true, calls: 9, duration_ms: 1302 },
      ],
      stats: failed
        ? undefined
        : {
            open_by_severity: {
              CRITICAL: Math.max(0, Math.round(12 + decay * 0.35)),
              HIGH: Math.max(0, Math.round(24 + decay * 0.6)),
              MEDIUM: Math.round(16 + decay * 0.3),
              LOW: Math.round(4 + (i % 3)),
            },
            new: Math.floor(rand(`new${i}`) * 6),
            fixed: Math.floor(rand(`fixed${i}`) * 8),
            repos: 11,
          },
      error: failed ? "all sources failed: osv: dial tcp: i/o timeout" : undefined,
    });
  }
  return runs;
}

export interface JobSeed {
  job: Job;
  events: JobEvent[];
}

export function makeJobs(): JobSeed[] {
  const seeds: JobSeed[] = [];
  let eventId = 1;
  const ev = (job_id: number, at: number, level: JobEvent["level"], message: string, repo?: string): JobEvent => ({
    id: eventId++,
    job_id,
    at: iso(at),
    level,
    message,
    repo,
  });
  const runs = makeRuns();
  // Scheduled jobs that produced the recent runs.
  runs.slice(-4).forEach((run, idx) => {
    const id = 40 + idx;
    const start = Date.parse(run.started_at);
    const ok = run.status !== "failed";
    seeds.push({
      job: {
        id,
        target_id: null,
        repo: "",
        trigger: "schedule",
        status: ok ? "succeeded" : "failed",
        run_id: run.id,
        attempts: 1,
        requested_by: "scheduler",
        error: ok ? undefined : run.error,
        created_at: iso(start - 2000),
        started_at: iso(start),
        finished_at: run.finished_at,
      },
      events: [
        ev(id, start, "info", "Scanning 3 targets"),
        ev(id, start + 20_000, "info", "Listed 11 repositories"),
        ...(run.repos_failed?.length ? [ev(id, start + 200_000, "error", "parse requirements.txt: line 12: invalid requirement", "globex/ml-models")] : []),
        ev(id, start + 300_000, "info", `Run #${run.id} finished: ${run.status}`),
      ],
    });
  });
  const t = NOW;
  seeds.push({
    job: {
      id: 50,
      target_id: 2,
      repo: "",
      trigger: "manual",
      status: "failed",
      run_id: null,
      attempts: 3,
      requested_by: "bob@acme.example",
      error: "list repos for org:globex: GET https://api.github.com/orgs/globex/repos: 401 Bad credentials",
      created_at: iso(t - 26 * H),
      started_at: iso(t - 26 * H + 1000),
      finished_at: iso(t - 26 * H + 9000),
    },
    events: [
      ev(50, t - 26 * H + 1000, "info", "Listing repositories for org:globex"),
      ev(50, t - 26 * H + 3000, "warn", "Attempt 1 failed: 401 Bad credentials; retrying"),
      ev(50, t - 26 * H + 6000, "warn", "Attempt 2 failed: 401 Bad credentials; retrying"),
      ev(50, t - 26 * H + 9000, "error", "list repos for org:globex: GET https://api.github.com/orgs/globex/repos: 401 Bad credentials"),
    ],
  });
  seeds.push({
    job: {
      id: 51,
      target_id: 1,
      repo: "acme/web",
      trigger: "manual",
      status: "canceled",
      run_id: null,
      attempts: 1,
      requested_by: ACTOR,
      created_at: iso(t - 20 * H),
      started_at: iso(t - 20 * H + 500),
      finished_at: iso(t - 20 * H + 4000),
    },
    events: [
      ev(51, t - 20 * H + 500, "info", "Fetching acme/web@main", "acme/web"),
      ev(51, t - 20 * H + 4000, "warn", "Canceled by alice@acme.example", "acme/web"),
    ],
  });
  seeds.push({
    job: {
      id: 52,
      target_id: 4,
      repo: "",
      branch: "release/2.x",
      trigger: "api",
      status: "running",
      run_id: null,
      attempts: 1,
      requested_by: "ci@acme.example",
      created_at: iso(t - 40_000),
      started_at: iso(t - 38_000),
      finished_at: null,
    },
    events: [
      ev(52, t - 38_000, "info", "Scanning repo:acme/legacy-billing@release/2.x"),
      ev(52, t - 30_000, "info", "git fetch --depth 1 origin release/2.x (mirror cache hit)", "acme/legacy-billing"),
    ],
  });
  seeds.push({
    job: {
      id: 53,
      target_id: 3,
      repo: "",
      trigger: "mcp",
      status: "queued",
      run_id: null,
      attempts: 0,
      requested_by: "claude-desktop",
      created_at: iso(t - 10_000),
      started_at: null,
      finished_at: null,
    },
    events: [],
  });
  return seeds;
}

export function makeSources(): SourceStatus[] {
  return [
    { name: "osv", kinds: ["vulnerability", "malicious"], healthy: true, last_seen: iso(NOW - 4 * H) },
    { name: "ghsa", kinds: ["vulnerability"], healthy: true, last_seen: iso(NOW - 4 * H) },
    { name: "nvd", kinds: ["cvss"], healthy: false, error: "429 Too Many Requests: set an NVD API key to raise the rate limit", last_seen: iso(NOW - 4 * H) },
    { name: "kev", kinds: ["exploited"], healthy: true, last_seen: iso(NOW - 4 * H) },
    { name: "epss", kinds: ["exploit-probability"], healthy: true, last_seen: iso(NOW - 4 * H) },
    { name: "endoflife", kinds: ["runtime"], healthy: true, last_seen: iso(NOW - 4 * H) },
    { name: "ai-agent", kinds: ["code"], healthy: true, last_seen: iso(NOW - 2 * D) },
  ];
}

export function makeNotifiers(): NotifierStatus[] {
  return [
    { name: "slack-security", type: "slack" },
    { name: "pagerduty-webhook", type: "webhook" },
  ];
}

export function makeAudit(): AuditEntry[] {
  const actions: [string, string, string][] = [
    ["target.update", "target", "2"],
    ["job.trigger", "job", "50"],
    ["finding.suppress", "finding", "-"],
    ["auth_profile.secret.replace", "auth_profile", "globex-app"],
    ["job.cancel", "job", "51"],
    ["target.create", "target", "3"],
    ["auth_profile.create", "auth_profile", "spare-token"],
    ["notifier.test", "notifier", "slack-security"],
  ];
  const actors = [ACTOR, "bob@acme.example", "carol@acme.example", "ci@acme.example"];
  const out: AuditEntry[] = [];
  for (let i = 0; i < 75; i++) {
    const [action, object_type, object_id] = actions[i % actions.length]!;
    out.push({
      id: 500 - i,
      at: iso(NOW - (i + 1) * 5.5 * H),
      actor: actors[i % actors.length]!,
      action,
      object_type,
      object_id,
      details: action === "finding.suppress" ? { reason: "False positive: code path unreachable", expires_at: iso(NOW + 30 * D) } : { via: i % 3 === 0 ? "api" : "ui" },
    });
  }
  return out;
}
