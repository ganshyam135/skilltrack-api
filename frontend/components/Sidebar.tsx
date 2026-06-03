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

  const navItemClass = (path: string) =>
    [
      "rounded-lg px-4 py-3 text-sm font-medium transition",
      pathname === path
        ? "bg-white text-slate-950"
        : "text-slate-300 hover:bg-slate-900 hover:text-white",
    ].join(" ");

  return (
    <aside className="border-b border-slate-800 bg-slate-950 p-4 lg:sticky lg:top-0 lg:flex lg:h-screen lg:w-72 lg:flex-col lg:justify-between lg:border-b-0 lg:border-r lg:p-6">
      <div>
        <Link href="/" className="inline-flex items-center">
          <span className="text-2xl font-semibold tracking-normal text-white">SkillTrack</span>
        </Link>

        <nav className="mt-6 flex gap-2 overflow-x-auto lg:mt-10 lg:flex-col lg:overflow-visible">
          {navItems.map((item) => (
            <Link key={item.href} href={item.href} className={navItemClass(item.href)}>
              {item.label}
            </Link>
          ))}
        </nav>
      </div>

      <div className="mt-4 hidden flex-col gap-3 lg:flex">
        <Link
          href="/"
          className="rounded-lg border border-slate-700 px-4 py-3 text-sm font-medium text-slate-300 transition hover:bg-slate-900 hover:text-white"
        >
          Home
        </Link>

        <button
          onClick={handleLogout}
          className="rounded-lg bg-white px-4 py-3 text-sm font-semibold text-slate-950 transition hover:bg-slate-200"
        >
          Logout
        </button>
      </div>
    </aside>
  );
}
