"use client";
import { useSession } from "next-auth/react";
import { useState } from "react";

export default function SettingsPage() {
  const { data: session } = useSession();
  const [apiKey, setApiKey] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function generateKey() {
    setLoading(true);
    setError(null);
    try {
      const token = (session as { vexisToken?: string } | null)?.vexisToken;
      if (!token) throw new Error("Sign in to generate an API key.");
      const r = await fetch(`${process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000"}/api/v1/auth/api-key`, {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${token}`,
        },
      });
      if (!r.ok) throw new Error("Could not generate an API key. Please sign in and try again.");
      const data = await r.json();
      setApiKey(data.api_key);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not generate an API key.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="max-w-2xl mx-auto px-6 py-12">
      <h1 className="text-2xl font-bold mb-8">Settings</h1>
      <section className="bg-bg-secondary border border-border-subtle rounded-lg p-6">
        <h2 className="text-lg font-semibold mb-4">API Key</h2>
        {error && <p role="alert" className="text-red-400 text-sm mb-4">{error}</p>}
        <p className="text-text-secondary text-sm mb-4">
          Use your API key with the <code className="font-mono bg-bg-primary px-1 rounded">X-VEXIS-API-Key</code> header for programmatic access.
        </p>
        {apiKey ? (
          <div className="font-mono text-sm bg-bg-primary border border-border-subtle p-3 rounded break-all">
            {apiKey}
          </div>
        ) : (
          <button
            onClick={generateKey}
            disabled={loading}
            className="px-4 py-2 bg-accent-primary text-bg-primary rounded font-semibold text-sm disabled:opacity-50"
          >
            {loading ? "Generating..." : "Generate API Key"}
          </button>
        )}
        <p className="text-text-tertiary text-xs mt-3">Generating a new key invalidates the previous one.</p>
      </section>
    </div>
  );
}
