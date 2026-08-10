import type { Metadata } from "next";
import Link from "next/link";
import "./globals.css";

export const metadata: Metadata = {
  title: "VulnShield — Repository Security Intelligence",
  description:
    "Evidence-grounded vulnerability reasoning: scan a GitHub repo, get a Repository Security Intelligence Score and ranked remediations.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <header className="border-b border-slate-800 bg-slate-900/60 backdrop-blur">
          <div className="mx-auto flex max-w-6xl items-center justify-between px-6 py-4">
            <Link href="/" className="flex items-center gap-2 font-semibold">
              <span aria-hidden className="text-xl">
                🛡️
              </span>
              <span className="text-lg tracking-tight text-white">VulnShield</span>
              <span className="hidden text-xs text-slate-500 sm:inline">
                Repository Security Intelligence
              </span>
            </Link>
          </div>
        </header>
        <main className="mx-auto max-w-6xl px-6 py-8">{children}</main>
      </body>
    </html>
  );
}
