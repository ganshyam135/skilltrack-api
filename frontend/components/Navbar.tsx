"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

const navLinks = [
  { href: "/dashboard", label: "Dashboard" },
  { href: "/login", label: "Login" },
  { href: "/signup", label: "Sign Up" },
];

export default function Navbar() {
  const pathname = usePathname();

  const isActiveRoute = (path: string) => pathname === path;

  const navLinkClass = (path: string) =>
    [
      "rounded-lg px-4 py-2 text-sm font-medium transition",
      "focus:outline-none focus:ring-2 focus:ring-teal-400/70",
      isActiveRoute(path)
        ? "bg-white text-slate-950"
        : "text-slate-300 hover:bg-slate-900 hover:text-white",
    ].join(" ");

  return (
    <nav className="flex w-full items-center justify-between border-b border-slate-800 px-5 py-5 sm:px-8">
      <Link
        href="/dashboard"
        className="rounded-lg text-2xl font-bold tracking-normal text-white focus:outline-none focus:ring-2 focus:ring-teal-400/70"
      >
        SkillTrack
      </Link>

      <div className="flex items-center gap-2">
        {navLinks.map((link) => (
          <Link
            key={link.href}
            href={link.href}
            aria-current={isActiveRoute(link.href) ? "page" : undefined}
            className={navLinkClass(link.href)}
          >
            {link.label}
          </Link>
        ))}
      </div>
    </nav>
  );
}
