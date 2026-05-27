"use client";

import Link from "next/link";

export default function Sidebar() {
  return (
    <aside className="w-64 min-h-screen border-r border-gray-800 bg-black p-6">
      <h1 className="text-3xl font-bold text-white">SkillTrack</h1>

      <nav className="mt-10 flex flex-col gap-3">
        <Link
          href="/dashboard"
          className="rounded-xl px-4 py-3 text-gray-300 hover:bg-gray-900 hover:text-white transition"
        >
          Dashboard
        </Link>

        <Link
          href="/goals"
          className="rounded-xl px-4 py-3 text-gray-300 hover:bg-gray-900 hover:text-white transition"
        >
          Goals
        </Link>

        <Link
          href="/skills"
          className="rounded-xl px-4 py-3 text-gray-300 hover:bg-gray-900 hover:text-white transition"
        >
          Skills
        </Link>

        <Link
          href="/sessions"
          className="rounded-xl px-4 py-3 text-gray-300 hover:bg-gray-900 hover:text-white transition"
        >
          Study Sessions
        </Link>

        <Link
          href="/analytics"
          className="rounded-xl px-4 py-3 text-gray-300 hover:bg-gray-900 hover:text-white transition"
        >
          Analytics
        </Link>
      </nav>
    </aside>
  );
}
