/**
 * Benchmark Repository Catalog
 *
 * Curated list of intentionally vulnerable or historically vulnerable public
 * repositories used to evaluate the RSIS pipeline across diverse ecosystems,
 * languages, and vulnerability profiles.
 *
 * Selection criteria:
 *   - Publicly accessible on GitHub (no auth required for tree/manifest reads)
 *   - Contains npm, Maven, or PyPI package manifests
 *   - Has a documented vulnerability history
 *   - Represents a range of RSIS score profiles (low → high)
 */
export interface BenchmarkRepo {
  /** Human-readable display name */
  name: string;
  /** GitHub "owner/repo" slug */
  repoUrl: string;
  /** Primary ecosystem to focus scan on */
  ecosystem: "npm" | "maven" | "pypi";
  /** Expected vulnerability profile (informational only) */
  description: string;
  /** Expected rough RSIS range before remediation (for sanity checking) */
  expectedRsisBefore: [number, number];
}

export const BENCHMARK_REPOS: BenchmarkRepo[] = [
  {
    name: "OWASP Juice Shop",
    repoUrl: "juice-shop/juice-shop",
    ecosystem: "npm",
    description: "Intentionally insecure Node.js/Express web application. Dense npm dependency tree with many known CVEs.",
    expectedRsisBefore: [30, 60],
  },
  {
    name: "OWASP NodeGoat",
    repoUrl: "OWASP/NodeGoat",
    ecosystem: "npm",
    description: "Node.js application demonstrating OWASP Top 10 vulnerabilities. Older dependency tree with multiple high-severity CVEs.",
    expectedRsisBefore: [25, 55],
  },
  {
    name: "OWASP WebGoat",
    repoUrl: "WebGoat/WebGoat",
    ecosystem: "maven",
    description: "Java/Maven application for security training. Contains Spring and Apache vulnerabilities.",
    expectedRsisBefore: [35, 65],
  },
  {
    name: "OWASP PyGoat",
    repoUrl: "OWASP/PyGoat",
    ecosystem: "pypi",
    description: "Python/Django intentionally vulnerable web app. Covers PyPI dependency CVEs.",
    expectedRsisBefore: [30, 60],
  },
  {
    name: "DVWA (PHP placeholder — npm tooling)",
    repoUrl: "nicowillis/VulnerableApp",
    ecosystem: "npm",
    description: "Node.js vulnerable application for testing dependency scanning pipelines.",
    expectedRsisBefore: [20, 50],
  },
  {
    name: "Damn Vulnerable Node App",
    repoUrl: "appsecco/dvna",
    ecosystem: "npm",
    description: "Node.js application from Appsecco demonstrating DVWA-style vulnerabilities in Node.js. Well-known CVE-heavy dependency set.",
    expectedRsisBefore: [15, 45],
  },
  {
    name: "RailsGoat",
    repoUrl: "OWASP/railsgoat",
    ecosystem: "npm",
    description: "Ruby on Rails vulnerable app — includes a package.json with frontend npm deps.",
    expectedRsisBefore: [40, 70],
  },
  {
    name: "VulnLab Node",
    repoUrl: "thesp0nge/codebreaker",
    ecosystem: "npm",
    description: "Lightweight vulnerable Node.js app used in ctf/training contexts.",
    expectedRsisBefore: [20, 55],
  },
];
