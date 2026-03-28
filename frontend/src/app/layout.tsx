import type { Metadata } from "next";
import "./globals.css";
import AuthProvider from "@/components/AuthProvider";
import NavBar from "@/components/NavBar";

export const metadata: Metadata = {
  title: "VEXIS — Vulnerability EXploration & Inference System",
  description: "AI-powered zero-day vulnerability discovery",
  icons: { icon: "/favicon.svg" },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="bg-bg-primary text-text-primary font-body antialiased">
        <AuthProvider>
          <NavBar />
          <div className="pt-14">{children}</div>
        </AuthProvider>
      </body>
    </html>
  );
}
