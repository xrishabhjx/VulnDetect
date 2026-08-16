"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { RepositoryForm } from "@/components/scan-input/RepositoryForm";
import { ErrorMessage } from "@/components/common/Loading";
import { ReasoningChain } from "@/components/evidence/ReasoningChain";
import { RsisCard } from "@/components/evidence/RsisCard";

const exampleReasoningSteps = [
  {
    stepNumber: 1,
    observed: "express version 4.17.1 specified in package.json",
    evidence: "CVE-2024-21538 (OSV + NVD + CISA KEV)",
    deduced: "Matches high-severity ReDoS vulnerability in routing layer",
  },
  {
    stepNumber: 2,
    observed: "path-to-regexp imported in 4 internal route handlers",
    evidence: "src/router/index.ts:14-42 (Repository Knowledge Graph)",
    deduced: "Vulnerability is reachable along public API authentication endpoints",
  },
  {
    stepNumber: 3,
    observed: "Similar repository (nestjs/nest) resolved by updating dependency",
    evidence: "Vector similarity match: nestjs/nest (Health Score 92/100)",
    deduced: "Upgrading to express@4.19.2 resolves CVE with 0 breaking API changes (low SemVer risk)",
  },
];

export default function Home() {
  const router = useRouter();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleScan = (url: string, scanType: "quick" | "full") => {
    setLoading(true);
    setError(null);
    const encodedUrl = encodeURIComponent(url);
    router.push(`/scans/new?url=${encodedUrl}&type=${scanType}`);
  };

  return (
    <div className="min-h-screen bg-background text-primary">
      {/* Hero Section */}
      <section className="py-20 lg:py-24 border-b border-border">
        <div className="max-w-6xl mx-auto px-6">
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-12 lg:gap-16 items-center">
            {/* Left Column (60%) */}
            <div className="lg:col-span-7 space-y-8">
              <div className="space-y-4">
                <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-accent/10 border border-accent/20 text-accent font-mono text-xs uppercase tracking-wider">
                  <span>AI-Powered Vulnerability Detection & Remediation</span>
                </div>
                <h1 className="text-4xl sm:text-5xl lg:text-[58px] font-display font-bold text-primary leading-[1.08] tracking-tight">
                  Evidence-first repository security intelligence.
                </h1>
                <p className="text-lg text-secondary font-body leading-relaxed max-w-[65ch]">
                  VulnShield builds repository knowledge graphs and uses LLMs to generate ranked remediations with explicit{" "}
                  <span className="text-primary font-medium">Observed → Deduced</span> reasoning chains grounded in real code evidence.
                </p>
              </div>

              {error && (
                <ErrorMessage message={error} onDismiss={() => setError(null)} />
              )}

              {/* Action Buttons (side-by-side gap-3) */}
              <div className="flex flex-wrap items-center gap-3 pt-2">
                <a href="#start-scan" className="btn btn-primary">
                  Start Analysis
                </a>
                <a
                  href="#reasoning-chain"
                  className="btn btn-secondary"
                >
                  View Reasoning Spec
                </a>
              </div>
            </div>

            {/* Right Column: Real RSIS Preview Card (40%) */}
            <div className="lg:col-span-5 flex justify-center lg:justify-end">
              <RsisCard
                repoName="expressjs/express"
                vulnerability="CVE-2024-21538"
                rsiScore={72}
                grade="C"
                severity="high"
                remediation="Upgrade express@4.19.2+"
                impact="Mitigates ReDoS vulnerability in path-to-regexp router"
              />
            </div>
          </div>
        </div>
      </section>

      {/* Hairline Divider */}
      <div className="divider" />

      {/* Signature Element Section: Reasoning Chain */}
      <section id="reasoning-chain" className="py-20 lg:py-24 border-b border-border">
        <div className="max-w-6xl mx-auto px-6">
          <div className="max-w-3xl mb-12 space-y-3">
            <span className="text-xs font-mono uppercase tracking-wider text-accent">
              Signature Architecture
            </span>
            <h2 className="text-3xl sm:text-4xl font-display font-semibold text-primary">
              Structured Observed → Deduced Reasoning
            </h2>
            <p className="text-secondary text-base font-body leading-relaxed">
              Unlike generic scanners that output raw CVE lists, VulnShield establishes a clear chain of evidence for every recommendation.
            </p>
          </div>

          <div className="card p-8 bg-surface/80 border-border">
            <ReasoningChain steps={exampleReasoningSteps} isPreview={true} />
          </div>
        </div>
      </section>

      {/* Hairline Divider */}
      <div className="divider" />

      {/* Start Analysis Form Section */}
      <section id="start-scan" className="py-20 lg:py-24">
        <div className="max-w-3xl mx-auto px-6">
          <div className="card p-8 sm:p-10 space-y-8">
            <div className="space-y-2 border-b border-border pb-6">
              <span className="text-xs font-mono uppercase tracking-wider text-secondary">
                Diagnostic Console
              </span>
              <h2 className="text-2xl sm:text-3xl font-display font-semibold text-primary">
                Analyze a Repository
              </h2>
              <p className="text-secondary text-sm font-body">
                Enter any public GitHub repository URL to initiate dependency analysis and reasoning.
              </p>
            </div>

            <RepositoryForm onSubmit={handleScan} loading={loading} />

            <div className="pt-4 border-t border-border space-y-3">
              <span className="text-xs font-mono text-secondary uppercase tracking-wider">
                Sample Public Repositories:
              </span>
              <div className="flex flex-wrap gap-2.5">
                {[
                  "https://github.com/expressjs/express",
                  "https://github.com/django/django",
                  "https://github.com/vuejs/vue",
                ].map((url) => (
                  <button
                    key={url}
                    onClick={() => handleScan(url, "full")}
                    className="btn btn-secondary text-xs font-mono py-1.5 px-3"
                  >
                    {url.replace("https://github.com/", "")}
                  </button>
                ))}
              </div>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
}
