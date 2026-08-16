"use client";

interface LoadingSpinnerProps {
  size?: "sm" | "md" | "lg";
  text?: string;
}

export function LoadingSpinner({ size = "md", text }: LoadingSpinnerProps) {
  const sizeClasses = {
    sm: "w-4 h-4 border-2",
    md: "w-8 h-8 border-2",
    lg: "w-12 h-12 border-3",
  };

  return (
    <div className="flex flex-col items-center justify-center gap-3">
      <div className={`${sizeClasses[size]} border-border border-t-accent rounded-full animate-spin`} />
      {text && <p className="text-sm font-mono text-secondary">{text}</p>}
    </div>
  );
}

interface PipelineProgressProps {
  stage?: string;
  progress: number;
  stageLabel: string;
}

export function PipelineProgress({ progress, stageLabel }: PipelineProgressProps) {
  const stagesList = [
    "Fetching repository & metadata",
    "Parsing manifest files",
    "Querying OSV / NVD / Advisory DBs",
    "Building Repository Knowledge Graph",
    "Generating semantic embeddings",
    "Retrieving context & hybrid search",
    "Finding similar GitHub repos",
    "LLM reasoning chain generation",
    "Candidate validation",
    "Utility feature ranking",
    "Computing 5-dimension RSIS score",
    "Persisting analysis report",
  ];

  const currentIdx = Math.floor((progress / 100) * stagesList.length);

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="flex items-center justify-between">
        <div>
          <span className="text-xs font-mono uppercase tracking-wider text-secondary">
            13-Step Analysis Pipeline
          </span>
          <h3 className="text-lg font-display font-semibold text-primary">
            {stageLabel}
          </h3>
        </div>
        <span className="text-xl font-mono font-bold text-accent">
          {progress}%
        </span>
      </div>

      {/* Main Progress Bar */}
      <div className="w-full h-2 bg-surface border border-border rounded-full overflow-hidden">
        <div
          className="h-full bg-accent transition-all duration-300 ease-out"
          style={{ width: `${progress}%` }}
        />
      </div>

      {/* Vertical Pipeline Steps Visualizer */}
      <div className="relative pl-6 space-y-3 pt-2">
        <div className="absolute left-[7px] top-2 bottom-2 w-[1px] bg-border" />

        {stagesList.map((stepName, idx) => {
          const isDone = idx < currentIdx;
          const isCurrent = idx === currentIdx;

          return (
            <div key={idx} className="relative flex items-center justify-between text-xs font-mono">
              {/* Node dot */}
              <div
                className={`absolute -left-[24px] w-[15px] h-[15px] rounded-full border-2 flex items-center justify-center ${
                  isDone
                    ? "bg-accent border-accent"
                    : isCurrent
                    ? "bg-background border-accent pulse-dot"
                    : "bg-background border-border"
                }`}
              >
                {isDone && <div className="w-[5px] h-[5px] rounded-full bg-background" />}
                {isCurrent && <div className="w-[5px] h-[5px] rounded-full bg-accent" />}
              </div>

              <span
                className={`font-body text-sm ${
                  isDone
                    ? "text-primary"
                    : isCurrent
                    ? "text-accent font-medium"
                    : "text-secondary/60"
                }`}
              >
                Step {idx + 1}: {stepName}
              </span>

              <span className="text-[11px]">
                {isDone ? (
                  <span className="text-low font-mono">DONE</span>
                ) : isCurrent ? (
                  <span className="text-accent font-mono">RUNNING...</span>
                ) : (
                  <span className="text-secondary/40 font-mono">WAITING</span>
                )}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

interface ErrorMessageProps {
  message: string;
  onDismiss?: () => void;
}

export function ErrorMessage({ message, onDismiss }: ErrorMessageProps) {
  return (
    <div className="p-4 rounded-lg bg-critical/10 border border-critical/30 text-primary text-sm font-body">
      <div className="flex items-start justify-between gap-3">
        <div className="space-y-1">
          <p className="font-mono text-xs text-critical uppercase font-semibold">
            Analysis Execution Error
          </p>
          <p className="text-secondary text-sm leading-relaxed">{message}</p>
        </div>
        {onDismiss && (
          <button
            onClick={onDismiss}
            className="text-secondary hover:text-primary text-sm font-mono"
          >
            ✕
          </button>
        )}
      </div>
    </div>
  );
}
