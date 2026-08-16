"use client";

import Link from "next/link";
import { useState } from "react";
import { usePathname } from "next/navigation";

export function Header() {
  const [menuOpen, setMenuOpen] = useState(false);
  const pathname = usePathname();

  const navLinks = [
    { href: "/", label: "New Scan" },
    { href: "/scans", label: "Scan History" },
  ];

  return (
    <header className="bg-surface/90 border-b border-border sticky top-0 z-40 backdrop-blur-md">
      <div className="max-w-6xl mx-auto px-6 h-16 flex items-center justify-between">
        {/* Nav Logo (18-20px, Space Grotesk 600) */}
        <Link href="/" className="flex items-center gap-2.5 group">
          <div className="w-7 h-7 rounded-md bg-accent/15 border border-accent/30 flex items-center justify-center text-accent text-sm font-mono font-bold">
            🛡️
          </div>
          <span className="text-[19px] font-display font-semibold text-primary group-hover:text-accent transition-colors">
            VulnShield
          </span>
        </Link>

        {/* Desktop Nav */}
        <nav className="hidden md:flex items-center gap-8 font-body text-sm">
          {navLinks.map((link) => {
            const isActive = pathname === link.href;
            return (
              <Link
                key={link.href}
                href={link.href}
                className={`transition-colors ${
                  isActive
                    ? "text-primary font-medium"
                    : "text-secondary hover:text-accent"
                }`}
              >
                {link.label}
              </Link>
            );
          })}
        </nav>

        {/* Mobile Hamburger */}
        <button
          onClick={() => setMenuOpen(!menuOpen)}
          className="md:hidden text-secondary hover:text-primary p-2 font-mono text-sm"
          aria-label="Toggle menu"
        >
          {menuOpen ? "✕" : "☰"}
        </button>
      </div>

      {/* Mobile Drawer */}
      {menuOpen && (
        <div className="md:hidden border-t border-border bg-surface p-6 space-y-4 font-body text-sm">
          {navLinks.map((link) => (
            <Link
              key={link.href}
              href={link.href}
              onClick={() => setMenuOpen(false)}
              className="block text-secondary hover:text-accent py-1"
            >
              {link.label}
            </Link>
          ))}
        </div>
      )}
    </header>
  );
}

export function Footer() {
  return (
    <footer className="bg-surface/50 border-t border-border py-12">
      <div className="max-w-6xl mx-auto px-6 flex flex-col md:flex-row items-center justify-between gap-6 text-xs text-secondary font-body">
        <div className="space-y-1 text-center md:text-left">
          <p className="text-primary font-medium font-display text-sm">
            VulnShield
          </p>
          <p>AI-Powered Repository Vulnerability Detection & Remediation System</p>
        </div>
        <div className="font-mono text-[11px] text-secondary/80 text-center md:text-right">
          Knowledge Graphs • Hybrid BM25+Dense Retrieval • RSIS 5-Dimension Scoring
        </div>
      </div>
    </footer>
  );
}
