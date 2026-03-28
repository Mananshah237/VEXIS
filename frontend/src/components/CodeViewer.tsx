"use client";

interface Props {
  code: string;
  language?: string;
  highlightLines?: number[];
  startLine?: number;
}

export function CodeViewer({ code, language = "python", highlightLines = [], startLine = 1 }: Props) {
  const lines = code.split("\n");

  return (
    <div className="bg-bg-elevated rounded-lg overflow-auto font-code text-sm border border-border">
      <div className="flex">
        <div className="select-none text-right text-text-muted pr-4 pl-4 py-4 border-r border-border min-w-[3rem]">
          {lines.map((_, i) => (
            <div key={i} className="leading-6">{startLine + i}</div>
          ))}
        </div>
        <pre className="flex-1 py-4 px-4 overflow-x-auto">
          {lines.map((line, i) => (
            <div
              key={i}
              className={`leading-6 ${highlightLines.includes(startLine + i) ? "bg-severity-critical/10 border-l-2 border-severity-critical pl-2 -ml-2" : ""}`}
            >
              {line || " "}
            </div>
          ))}
        </pre>
      </div>
    </div>
  );
}
