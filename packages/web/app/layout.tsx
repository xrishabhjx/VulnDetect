import { Space_Grotesk, Inter, JetBrains_Mono } from "next/font/google";
import "@/app/globals.css";
import { Layout } from "@/components/layout/Layout";

const spaceGrotesk = Space_Grotesk({
  subsets: ["latin"],
  weight: ["600", "700"],
  variable: "--font-space-grotesk",
  display: "swap",
});

const inter = Inter({
  subsets: ["latin"],
  weight: ["400", "500", "600"],
  variable: "--font-inter",
  display: "swap",
});

const jetbrainsMono = JetBrains_Mono({
  subsets: ["latin"],
  weight: ["400", "500"],
  variable: "--font-jetbrains-mono",
  display: "swap",
});

export const metadata = {
  title: "VulnShield — AI-Powered Vulnerability Detection & Remediation",
  description:
    "Scan GitHub repositories with intelligent knowledge graphs and LLM reasoning. Understand why each vulnerability matters with evidence-backed remediation.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html
      lang="en"
      className={`${spaceGrotesk.variable} ${inter.variable} ${jetbrainsMono.variable}`}
    >
      <body className="bg-background text-primary font-body antialiased">
        <Layout>{children}</Layout>
      </body>
    </html>
  );
}
