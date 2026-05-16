import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "ZeroDay — CVE Patch Sprinter",
  description:
    "Automatically respond to newly disclosed software vulnerabilities: analyze a target repository, generate a patch, run its tests, and produce a pull request.",
};

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
