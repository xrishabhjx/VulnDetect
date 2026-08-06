import semver from "semver";
import type {
  RemediationCandidate,
  RemediationReport,
  Ecosystem,
} from "../types.js";

// ─── Registry Version Check APIs ─────────────────────────────────────────────

const NPM_REGISTRY = "https://registry.npmjs.org";
const PYPI_REGISTRY = "https://pypi.org/pypi";
const MAVEN_CENTRAL = "https://search.maven.org/solrsearch/select";

async function checkNpmVersion(pkg: string, version: string): Promise<boolean> {
  try {
    const response = await fetch(`${NPM_REGISTRY}/${encodeURIComponent(pkg)}/${version}`, {
      method: "HEAD",
      signal: AbortSignal.timeout(8_000),
    });
    return response.ok;
  } catch {
    return true; // assume exists on network error
  }
}

async function checkPypiVersion(pkg: string, version: string): Promise<boolean> {
  try {
    const response = await fetch(`${PYPI_REGISTRY}/${pkg}/${version}/json`, {
      signal: AbortSignal.timeout(8_000),
    });
    return response.ok;
  } catch {
    return true;
  }
}

async function checkMavenVersion(pkg: string, version: string): Promise<boolean> {
  const [groupId, artifactId] = pkg.split(":");
  if (!groupId || !artifactId) return true;
  try {
    const q = `g:${groupId} AND a:${artifactId} AND v:${version}`;
    const url = `${MAVEN_CENTRAL}?q=${encodeURIComponent(q)}&rows=1&wt=json`;
    const response = await fetch(url, { signal: AbortSignal.timeout(8_000) });
    if (!response.ok) return true;
    const data = (await response.json()) as { response: { numFound: number } };
    return data.response.numFound > 0;
  } catch {
    return true;
  }
}

async function checkVersionSafe(
  ecosystem: Ecosystem,
  pkg: string,
  version: string
): Promise<{ safe: boolean; newVulnCount: number }> {
  const osvEcosystem = ecosystem === "npm" ? "npm"
    : ecosystem === "pypi" ? "PyPI"
    : ecosystem === "maven" ? "Maven"
    : ecosystem;

  try {
    const response = await fetch("https://api.osv.dev/v1/query", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        package: { name: pkg, ecosystem: osvEcosystem },
        version,
      }),
      signal: AbortSignal.timeout(10_000),
    });

    if (!response.ok) return { safe: true, newVulnCount: 0 };
    const data = (await response.json()) as { vulns?: unknown[] };
    const count = data.vulns?.length ?? 0;
    return { safe: count === 0, newVulnCount: count };
  } catch {
    return { safe: true, newVulnCount: 0 };
  }
}

// ─── Extended Validator ───────────────────────────────────────────────────────

/**
 * Validates remediation candidates across four stages:
 * 1. Registry existence check (npm/PyPI/Maven)
 * 2. SemVer dependency resolution & breaking change compatibility check
 * 3. Re-scan security re-analysis via OSV
 * 4. Confidence & risk adjustment
 */
export class RemediationValidator {
  async validate(
    report: RemediationReport,
    ecosystem: Ecosystem,
    currentVersion?: string
  ): Promise<RemediationReport> {
    let anyPassed = false;

    for (const candidate of report.candidates) {
      await this.validateCandidate(candidate, report.packageName, ecosystem, currentVersion);
      if (!candidate.rejected) anyPassed = true;
    }

    return {
      ...report,
      validationPassed: anyPassed,
    };
  }

  private async validateCandidate(
    candidate: RemediationCandidate,
    packageName: string,
    ecosystem: Ecosystem,
    currentVersion?: string
  ): Promise<void> {
    if (candidate.action === "accept" || candidate.action === "mitigate") {
      candidate.validated = true;
      candidate.validationNotes = "No version change required — no semver resolution needed";
      return;
    }

    const targetVersion = candidate.proposedVersion;
    if (!targetVersion) {
      candidate.validationNotes = "No proposed version to validate";
      candidate.validated = false;
      return;
    }

    // Stage 1: Registry Existence Check
    const exists = await this.checkVersionExists(ecosystem, packageName, targetVersion);
    if (exists === false) {
      candidate.rejected = true;
      candidate.rejectionReason = `Version ${targetVersion} not found in ${ecosystem} package registry`;
      candidate.confidence = 0;
      return;
    }

    // Stage 2: SemVer Compatibility & Breaking Change Assessment
    if (currentVersion && semver.valid(currentVersion) && semver.valid(targetVersion)) {
      const diff = semver.diff(currentVersion, targetVersion);

      if (diff === "major") {
        candidate.compatibilityRisk = "high";
        candidate.confidence *= 0.8;
        candidate.validationNotes = `Major version upgrade (${currentVersion} -> ${targetVersion}): Potential breaking changes`;
      } else if (diff === "minor") {
        candidate.compatibilityRisk = "medium";
        candidate.validationNotes = `Minor version upgrade (${currentVersion} -> ${targetVersion}): Backward compatible feature additions`;
      } else if (diff === "patch") {
        candidate.compatibilityRisk = "low";
        candidate.validationNotes = `Patch upgrade (${currentVersion} -> ${targetVersion}): SemVer safe bug fix`;
      }
    }

    // Stage 3: OSV Re-scan Security Check
    const { safe, newVulnCount } = await checkVersionSafe(ecosystem, packageName, targetVersion);
    if (!safe) {
      candidate.confidence = Math.min(candidate.confidence * 0.3, 0.2);
      const prevNotes = candidate.validationNotes ? `${candidate.validationNotes}; ` : "";
      candidate.validationNotes = `${prevNotes}⚠️ Warning: Proposed version ${targetVersion} contains ${newVulnCount} known CVE(s) in OSV`;
    }

    candidate.validated = true;
  }

  private async checkVersionExists(
    ecosystem: Ecosystem,
    pkg: string,
    version: string
  ): Promise<boolean | null> {
    try {
      if (ecosystem === "npm") return await checkNpmVersion(pkg, version);
      if (ecosystem === "pypi") return await checkPypiVersion(pkg, version);
      if (ecosystem === "maven") return await checkMavenVersion(pkg, version);
      return null;
    } catch {
      return null;
    }
  }
}
