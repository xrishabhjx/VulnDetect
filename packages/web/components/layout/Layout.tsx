"use client";

import React from "react";
import { Header, Footer } from "./Header";
import { ErrorBoundary } from "@/components/common/ErrorBoundary";

interface LayoutProps {
  children: React.ReactNode;
}

export function Layout({ children }: LayoutProps) {
  return (
    <ErrorBoundary>
      <div className="min-h-screen flex flex-col bg-background text-primary">
        <Header />
        <main className="flex-1">{children}</main>
        <Footer />
      </div>
    </ErrorBoundary>
  );
}
