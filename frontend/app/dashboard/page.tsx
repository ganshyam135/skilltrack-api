"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";

export default function DashboardPage() {
  const router = useRouter();

  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const token = localStorage.getItem("token");

    if (!token) {
      router.push("/login");
    } else {
      setLoading(false);
    }
  }, [router]);

  const handleLogout = () => {
    localStorage.removeItem("token");

    router.push("/login");
  };

  if (loading) {
    return (
      <main className="min-h-screen bg-black text-white flex items-center justify-center">
        Loading...
      </main>
    );
  }

  return (
    <main className="min-h-screen bg-black text-white">
      <div className="flex items-center justify-between px-8 py-6 border-b border-gray-800">
        <h1 className="text-3xl font-bold">Dashboard</h1>

        <button
          onClick={handleLogout}
          className="rounded-xl border border-gray-700 px-4 py-2 hover:bg-gray-900 transition"
        >
          Logout
        </button>
      </div>

      <section className="p-8">
        <div className="rounded-2xl border border-gray-800 bg-gray-950 p-6">
          <h2 className="text-2xl font-semibold">Welcome to SkillTrack 🚀</h2>

          <p className="mt-3 text-gray-400">
            Your personalized learning analytics dashboard is now active.
          </p>
        </div>
      </section>
    </main>
  );
}
