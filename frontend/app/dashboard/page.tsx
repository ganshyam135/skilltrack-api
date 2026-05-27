"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import DashboardCard from "@/components/DashboardCard";

export default function DashboardPage() {
  const router = useRouter();

  const [loading, setLoading] = useState(true);
  const [totalHours, setTotalHours] = useState("0.0");
  const [streak, setStreak] = useState(0);
  const [achievementCount, setAchievementCount] = useState(0);
  const [goalCount, setGoalCount] = useState(0);

  useEffect(() => {
    const token = localStorage.getItem("token");

    if (!token) {
      router.push("/login");
      return;
    }

    const loadDashboard = async () => {
      try {
        const headers = {
          Authorization: `Bearer ${token}`,
        };

        const [
          totalResponse,
          streakResponse,
          achievementResponse,
          goalsResponse,
        ] = await Promise.all([
          fetch("http://localhost:8000/analytics/total-time", { headers }),
          fetch("http://localhost:8000/analytics/streak", { headers }),
          fetch("http://localhost:8000/analytics/achievements", { headers }),
          fetch("http://localhost:8000/goals/", { headers }),
        ]);

        if (
          !totalResponse.ok ||
          !streakResponse.ok ||
          !achievementResponse.ok ||
          !goalsResponse.ok
        ) {
          throw new Error("Failed to load dashboard data");
        }

        const [totalData, streakData, achievementData, goalsData] =
          await Promise.all([
            totalResponse.json(),
            streakResponse.json(),
            achievementResponse.json(),
            goalsResponse.json(),
          ]);

        setTotalHours((Number(totalData.total_minutes ?? 0) / 60).toFixed(1));
        setStreak(Number(streakData.current_streak ?? 0));
        setAchievementCount(
          Array.isArray(achievementData.achievements)
            ? achievementData.achievements.length
            : 0,
        );
        setGoalCount(Array.isArray(goalsData) ? goalsData.length : 0);
      } catch (error) {
        console.error(error);
        localStorage.removeItem("token");
        router.push("/login");
      } finally {
        setLoading(false);
      }
    };

    void loadDashboard();
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
          <h2 className="text-2xl font-semibold">Welcome to SkillTrack</h2>

          <p className="mt-3 text-gray-400">
            Your personalized learning analytics dashboard is now active.
          </p>
        </div>

        <div className="mt-6 grid grid-cols-1 gap-6 md:grid-cols-2 xl:grid-cols-4">
          <DashboardCard title="Total Hours" value={`${totalHours}h`} />
          <DashboardCard title="Current Streak" value={`${streak} days`} />
          <DashboardCard
            title="Achievements"
            value={String(achievementCount)}
          />
          <DashboardCard title="Goals" value={String(goalCount)} />
        </div>
      </section>
    </main>
  );
}
