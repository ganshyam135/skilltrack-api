import Link from "next/link";

export default function Navbar() {
  return (
    <nav className="w-full flex items-center justify-between px-8 py-6 border-b border-gray-800">
      <h1 className="text-2xl font-bold tracking-tight">SkillTrack</h1>

      <div className="flex items-center gap-6 text-sm text-gray-300">
        <button className="hover:text-white transition">Features</button>

        <button className="hover:text-white transition">Analytics</button>

        <button className="hover:text-white transition">AI Insights</button>

        <Link
          href="/login"
          className="rounded-xl bg-white text-black px-4 py-2 font-medium hover:bg-gray-200 transition"
        >
          Login
        </Link>
      </div>
    </nav>
  );
}
