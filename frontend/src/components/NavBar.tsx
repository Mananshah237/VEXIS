"use client";
import { useSession, signIn, signOut } from "next-auth/react";
import Image from "next/image";
import Link from "next/link";

export default function NavBar() {
  const { data: session } = useSession();
  return (
    <nav className="fixed top-0 left-0 right-0 z-50 flex items-center justify-between px-6 py-3 bg-bg-secondary border-b border-border-subtle">
      <Link href="/" className="font-mono text-lg font-bold text-accent-primary">VEXIS</Link>
      <div className="flex items-center gap-4">
        {session?.user ? (
          <>
            <Link href="/dashboard" className="text-sm text-text-secondary hover:text-text-primary">Dashboard</Link>
            <Link href="/settings" className="text-sm text-text-secondary hover:text-text-primary">Settings</Link>
            <div className="flex items-center gap-2">
              {session.user.image && (
                <Image src={session.user.image} alt="avatar" width={28} height={28} className="rounded-full" />
              )}
              <span className="text-sm text-text-secondary">{session.user.name}</span>
            </div>
            <button
              onClick={() => signOut()}
              className="text-sm px-3 py-1 border border-border-subtle rounded hover:bg-bg-hover text-text-secondary"
            >
              Sign out
            </button>
          </>
        ) : (
          <button
            onClick={() => signIn("github")}
            className="text-sm px-4 py-1.5 bg-accent-primary text-bg-primary rounded font-semibold hover:bg-accent-hover"
          >
            Sign in with GitHub
          </button>
        )}
      </div>
    </nav>
  );
}
