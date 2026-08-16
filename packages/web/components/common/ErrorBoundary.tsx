"use client";

import React from "react";

interface ErrorBoundaryProps {
  children: React.ReactNode;
}

interface ErrorBoundaryState {
  hasError: boolean;
  error: Error | null;
}

export class ErrorBoundary extends React.Component<ErrorBoundaryProps, ErrorBoundaryState> {
  constructor(props: ErrorBoundaryProps) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo) {
    console.error("Error caught by boundary:", error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen bg-background flex items-center justify-center p-6">
          <div className="card max-w-md w-full p-8 text-center space-y-6">
            <div className="w-12 h-12 rounded-full bg-critical/15 border border-critical/30 mx-auto flex items-center justify-center font-mono font-bold text-critical text-xl">
              !
            </div>
            <div className="space-y-2">
              <h1 className="text-xl font-display font-semibold text-primary">System Error</h1>
              <p className="text-secondary text-sm font-body leading-relaxed">
                {this.state.error?.message || "An unexpected application error occurred."}
              </p>
            </div>
            <button
              onClick={() => window.location.reload()}
              className="btn btn-primary w-full"
            >
              Reload Page
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
