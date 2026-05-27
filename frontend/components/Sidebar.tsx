"use client";

import Link from "next/link";

import { usePathname, useRouter } from "next/navigation";

export default function Sidebar() {
  const pathname = usePathname();

  const router = useRouter();

  const handleLogout = () => {
    localStorage.removeItem("token");

    router.push("/login");
  };

  const navItemClass = (path: string) => {
    return `
      rounded-xl px-4 py-3 transition font-medium
      ${
        pathname === path
          ? "bg-white text-black"
          : "text-gray-300 hover:bg-gray-900 hover:text-white"
      }
    `;
  };

  return (
    <aside className="w-72 min-h-screen border-r border-gray-800 bg-black flex flex-col justify-between p-6">
      <div>
        <Link href="/">
          <h1 className="text-3xl font-bold cursor-pointer">SkillTrack</h1>
        </Link>

        <nav className="mt-10 flex flex-col gap-3">
          <Link href="/dashboard" className={navItemClass("/dashboard")}>
            Dashboard
          </Link>

          <Link href="/skills" className={navItemClass("/skills")}>
            Skills
          </Link>

          <Link href="/sessions" className={navItemClass("/sessions")}>
            Study Sessions
          </Link>

          <Link href="/goals" className={navItemClass("/goals")}>
            Goals
          </Link>

          <Link href="/analytics" className={navItemClass("/analytics")}>
            Analytics
          </Link>
        </nav>
      </div>

      <div className="flex flex-col gap-3">
        <Link
          href="/"
          className="rounded-xl border border-gray-700 px-4 py-3 text-gray-300 hover:bg-gray-900 hover:text-white transition font-medium"
        >
          Home
        </Link>

        <button
          onClick={handleLogout}
          className="rounded-xl bg-white text-black px-4 py-3 font-semibold hover:bg-gray-200 transition"
        >
          Logout
        </button>
      </div>
    </aside>
  );
}
