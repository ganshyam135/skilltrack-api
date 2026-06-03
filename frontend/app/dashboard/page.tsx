"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import AchievementsCard from "@/components/AchievementsCard";
import AIInsights from "@/components/AIInsights";
import DashboardCard from "@/components/DashboardCard";
import RecentActivity from "@/components/RecentActivity";
import Sidebar from "@/components/Sidebar";
import SkillBreakdown from "@/components/SkillBreakdown";
import StudyHeatmap from "@/components/StudyHeatmap";
import WeeklyChart from "@/components/WeeklyChart";

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

type WeeklyPoint = {
  date: string;
  minutes: number;
};

type SkillBreakdownPoint = {
  skill: string;
  minutes: number;
};

type Session = {
  id: number;
  duration: number;
  notes: string | null;
  created_at: string;
};

type HeatmapDay = {
  date: string;
  sessions: number;
  total_minutes: number;
};

type DashboardData = {
  totalHours: string;
  streak: number;
  longestStreak: number;
  achievementCount: number;
  goalCount: number;
  weeklyData: WeeklyPoint[];
  insights: string[];
  skillBreakdown: SkillBreakdownPoint[];
  recentSessions: Session[];
  achievements: string[];
  heatmapData: HeatmapDay[];
};

const emptyDashboardData: DashboardData = {
  totalHours: "0.0",
  streak: 0,
  longestStreak: 0,
  achievementCount: 0,
  goalCount: 0,
  weeklyData: [],
  insights: [],
  skillBreakdown: [],
  recentSessions: [],
  achievements: [],
  heatmapData: [],
};

async function fetchJson<T>(url: string, token: string): Promise<T> {
  const response = await fetch(url, {
    headers: { Authorization: `Bearer ${token}` },
  });

  if (response.status === 401 || response.status === 403) {
    throw new Error("AUTH_EXPIRED");
  }

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`${response.status} ${errorText || response.statusText}`);
  }

  return response.json() as Promise<T>;
}

export default function DashboardPage() {
  const router = useRouter();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [data, setData] = useState<DashboardData>(emptyDashboardData);

  const fetchDashboardData = useCallback(async () => {
    const token = localStorage.getItem("token");

    if (!token) {
      router.push("/login");
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const [
        totalData,
        streakData,
        achievementData,
        goalsData,
        weeklyData,
        insightsData,
        skillBreakdown,
        recentSessions,
        heatmapData,
      ] = await Promise.all([
        fetchJson<{ total_minutes: number }>(`${API_URL}/analytics/total-time`, token),
        fetchJson<{
          current_streak: number;
          longest_streak: number;
          last_study_date: string | null;
        }>(`${API_URL}/analytics/streak`, token),
        fetchJson<{ achievements: string[] }>(`${API_URL}/analytics/achievements`, token),
        fetchJson<unknown[]>(`${API_URL}/goals`, token),
        fetchJson<WeeklyPoint[]>(`${API_URL}/analytics/weekly-summary`, token),
        fetchJson<{ insights: string[] }>(`${API_URL}/analytics/ai-insights`, token),
        fetchJson<SkillBreakdownPoint[]>(`${API_URL}/analytics/skill-breakdown`, token),
        fetchJson<Session[]>(`${API_URL}/sessions?limit=5`, token),
        fetchJson<HeatmapDay[]>(`${API_URL}/analytics/heatmap`, token),
      ]);

      setData({
        totalHours: (totalData.total_minutes / 60).toFixed(1),
        streak: streakData.current_streak,
        longestStreak: streakData.longest_streak,
        achievementCount: achievementData.achievements.length,
        goalCount: goalsData.length,
        weeklyData,
        insights: insightsData.insights,
        skillBreakdown,
        recentSessions,
        achievements: achievementData.achievements,
        heatmapData,
      });
    } catch (fetchError) {
      if (fetchError instanceof Error && fetchError.message === "AUTH_EXPIRED") {
        localStorage.removeItem("token");
        router.push("/login");
        return;
      }

      setError("Dashboard data could not be loaded. Check that the API is running and try again.");
    } finally {
      setLoading(false);
    }
  }, [router]);

  useEffect(() => {
    queueMicrotask(() => {
      void fetchDashboardData();
    });
  }, [fetchDashboardData]);

  const totalSessions = useMemo(
    () => data.heatmapData.reduce((sum, day) => sum + day.sessions, 0),
    [data.heatmapData],
  );

  const handleLogout = () => {
    localStorage.removeItem("token");
    router.push("/login");
  };

  if (loading) {
    return (
      <main className="flex min-h-screen items-center justify-center bg-slate-950 text-white">
        <div className="rounded-lg border border-slate-800 bg-slate-900 px-5 py-4 text-sm text-slate-300">
          Loading dashboard...
        </div>
      </main>
    );
  }

  return (
    <main className="min-h-screen bg-slate-950 text-white lg:flex">
      <Sidebar />

      <div className="min-w-0 flex-1">
        <header className="border-b border-slate-800 bg-slate-950/95 px-5 py-6 sm:px-8">
          <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
            <div>
              <p className="text-sm font-medium uppercase text-teal-300">Learning Command Center</p>
              <h1 className="mt-2 text-3xl font-semibold tracking-normal text-white">Dashboard</h1>
              <p className="mt-2 max-w-2xl text-sm text-slate-400">
                Track time, consistency, goals, and skill momentum from one workspace.
              </p>
            </div>

            <div className="flex flex-wrap items-center gap-3">
              <button
                onClick={() => void fetchDashboardData()}
                className="rounded-lg border border-slate-700 px-4 py-2 text-sm font-medium text-slate-200 transition hover:bg-slate-900"
              >
                Refresh
              </button>
              <button
                onClick={handleLogout}
                className="rounded-lg bg-white px-4 py-2 text-sm font-semibold text-slate-950 transition hover:bg-slate-200"
              >
                Logout
              </button>
            </div>
          </div>
        </header>

        <div className="space-y-6 p-5 sm:p-8">
          {error ? (
            <div className="rounded-lg border border-red-900 bg-red-950/40 p-4 text-sm text-red-100">
              <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                <p>{error}</p>
                <button
                  onClick={() => void fetchDashboardData()}
                  className="rounded-lg border border-red-800 px-3 py-2 font-medium transition hover:bg-red-900/50"
                >
                  Retry
                </button>
              </div>
            </div>
          ) : null}

          <section className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
            <DashboardCard title="Study Hours" value={`${data.totalHours} hrs`} detail="Total logged time" />
            <DashboardCard
              title="Current Streak"
              value={`${data.streak} days`}
              detail={`Best streak: ${data.longestStreak} days`}
            />
            <DashboardCard
              title="Sessions"
              value={`${totalSessions}`}
              detail="Across active history"
            />
            <DashboardCard title="Goals" value={`${data.goalCount}`} detail={`${data.achievementCount} achievements`} />
          </section>

          <section className="grid grid-cols-1 gap-6 xl:grid-cols-[minmax(0,1.5fr)_minmax(360px,1fr)]">
            <WeeklyChart data={data.weeklyData} />
            <AIInsights insights={data.insights} />
          </section>

          <section className="grid grid-cols-1 gap-6 xl:grid-cols-2">
            <SkillBreakdown data={data.skillBreakdown} />
            <StudyHeatmap data={data.heatmapData} />
          </section>

          <section className="grid grid-cols-1 gap-6 xl:grid-cols-2">
            <RecentActivity sessions={data.recentSessions} />
            <AchievementsCard achievements={data.achievements} />
          </section>
        </div>
      </div>
    </main>
  );
}
