"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";

const navItems = [
  { href: "/dashboard", label: "Dashboard" },
  { href: "/skills", label: "Skills" },
  { href: "/sessions", label: "Study Sessions" },
  { href: "/goals", label: "Goals" },
];

export default function Sidebar() {
  const pathname = usePathname();
  const router = useRouter();

  const handleLogout = () => {
    localStorage.removeItem("token");
    router.push("/login");
  };

  const isActiveRoute = (path: string) =>
    pathname === path || pathname.startsWith(`${path}/`);

  const navItemClass = (path: string) =>
    [
      "block rounded-lg px-4 py-3 text-sm font-medium transition",
      "focus:outline-none focus:ring-2 focus:ring-teal-400/70",
      isActiveRoute(path)
        ? "bg-white text-slate-950 shadow-sm"
        : "text-slate-300 hover:bg-slate-900 hover:text-white",
    ].join(" ");

  return (
    <aside className="shrink-0 border-b border-slate-800 bg-slate-950 px-4 py-4 lg:sticky lg:top-0 lg:flex lg:h-screen lg:w-72 lg:flex-col lg:justify-between lg:border-b-0 lg:border-r lg:px-6 lg:py-6">
      <div>
        <Link
          href="/dashboard"
          className="inline-flex rounded-lg focus:outline-none focus:ring-2 focus:ring-teal-400/70"
        >
          <span className="text-2xl font-semibold tracking-normal text-white">
            SkillTrack
          </span>
        </Link>

        <div className="mt-6 lg:mt-10">
          <p className="mb-3 px-4 text-xs font-semibold uppercase tracking-wide text-slate-500">
            Workspace
          </p>

          <nav
            aria-label="Primary navigation"
            className="flex gap-2 overflow-x-auto pb-1 lg:flex-col lg:overflow-visible lg:pb-0"
          >
            {navItems.map((item) => (
              <Link
                key={item.href}
                href={item.href}
                aria-current={isActiveRoute(item.href) ? "page" : undefined}
                className={navItemClass(item.href)}
              >
                {item.label}
              </Link>
            ))}
          </nav>
        </div>
      </div>

      <div className="mt-6 hidden lg:block">
        <button
          onClick={handleLogout}
          className="w-full rounded-lg bg-white px-4 py-3 text-sm font-semibold text-slate-950 transition hover:bg-slate-200 focus:outline-none focus:ring-2 focus:ring-teal-400/70"
        >
          Logout
        </button>
      </div>
    </aside>
  );
}
