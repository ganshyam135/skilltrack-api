"use client";

import { useCallback, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import DashboardCard from "@/components/DashboardCard";
import WeeklyChart from "@/components/WeeklyChart";

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

export default function DashboardPage() {
  const router = useRouter();

  const [loading, setLoading] = useState(true);
  const [totalHours, setTotalHours] = useState<string>("0");
  const [streak, setStreak] = useState(0);
  const [achievementCount, setAchievementCount] = useState(0);
  const [goalCount, setGoalCount] = useState(0);
  const [weeklyData, setWeeklyData] = useState([]);

  const fetchDashboardData = useCallback(async (token: string) => {
    try {
      const headers = { Authorization: `Bearer ${token}` };

      const [
        totalResponse,
        streakResponse,
        achievementResponse,
        goalsResponse,
        weeklyResponse,
      ] = await Promise.all([
        fetch(`${API_URL}/analytics/total-time`, { headers }),
        fetch(`${API_URL}/analytics/streak`, { headers }),
        fetch(`${API_URL}/analytics/achievements`, { headers }),
        fetch(`${API_URL}/goals`, { headers }),
        fetch(`${API_URL}/analytics/weekly-summary`, { headers }),
      ]);

      if (!totalResponse.ok) throw new Error("Failed to fetch total time");
      if (!streakResponse.ok) throw new Error("Failed to fetch streak");
      if (!achievementResponse.ok)
        throw new Error("Failed to fetch achievements");
      if (!goalsResponse.ok) throw new Error("Failed to fetch goals");
      if (!weeklyResponse.ok) throw new Error("Failed to fetch weekly summary");

      const [
        totalData,
        streakData,
        achievementData,
        goalsData,
        weeklyDataResponse,
      ] = await Promise.all([
        totalResponse.json(),
        streakResponse.json(),
        achievementResponse.json(),
        goalsResponse.json(),
        weeklyResponse.json(),
      ]);

      setTotalHours((totalData.total_minutes / 60).toFixed(1));
      setStreak(streakData.current_streak);
      setAchievementCount(achievementData.achievements.length);
      setGoalCount(goalsData.length);
      setWeeklyData(weeklyDataResponse);
    } catch (error) {
      console.error(error);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    const token = localStorage.getItem("token");

    if (!token) {
      router.push("/login");
    } else {
      fetchDashboardData(token);
    }
  }, [router, fetchDashboardData]);

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

      <section className="p-8 grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-6">
        <DashboardCard title="Total Study Hours" value={`${totalHours} hrs`} />
        <DashboardCard title="Current Streak" value={`${streak} days`} />
        <DashboardCard title="Achievements" value={`${achievementCount}`} />
        <DashboardCard title="Goals" value={`${goalCount}`} />
      </section>

      <section className="px-8 pb-10">
        <WeeklyChart data={weeklyData} />
      </section>
    </main>
  );
}
