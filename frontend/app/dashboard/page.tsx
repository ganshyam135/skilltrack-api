"use client";

import { useCallback, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import DashboardCard from "@/components/DashboardCard";
import WeeklyChart from "@/components/WeeklyChart";
import AIInsights from "@/components/AIInsights";
import Sidebar from "@/components/Sidebar";
import SkillBreakdown from "@/components/SkillBreakdown";
import RecentActivity from "@/components/RecentActivity";
import AchievementsCard from "@/components/AchievementsCard";
import StudyHeatmap from "@/components/StudyHeatmap";

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

export default function DashboardPage() {
  const router = useRouter();

  const [loading, setLoading] = useState(true);
  const [totalHours, setTotalHours] = useState<string>("0");
  const [streak, setStreak] = useState(0);
  const [achievementCount, setAchievementCount] = useState(0);
  const [goalCount, setGoalCount] = useState(0);
  const [weeklyData, setWeeklyData] = useState([]);
  const [insights, setInsights] = useState<string[]>([]);
  const [skillBreakdown, setSkillBreakdown] = useState([]);
  const [recentSessions, setRecentSessions] = useState([]);
  const [achievements, setAchievements] = useState<string[]>([]);
  const [heatmapData, setHeatmapData] = useState([]);

  const fetchDashboardData = useCallback(
    async (token: string) => {
      try {
        const headers = { Authorization: `Bearer ${token}` };

        const [
          totalResponse,
          streakResponse,
          achievementResponse,
          goalsResponse,
          weeklyResponse,
          aiInsightsResponse,
          skillBreakdownResponse,
          recentSessionsResponse,
          heatmapResponse,
        ] = await Promise.all([
          fetch(`${API_URL}/analytics/total-time`, { headers }),
          fetch(`${API_URL}/analytics/streak`, { headers }),
          fetch(`${API_URL}/analytics/achievements`, { headers }),
          fetch(`${API_URL}/goals`, { headers }),
          fetch(`${API_URL}/analytics/weekly-summary`, { headers }),
          fetch(`${API_URL}/analytics/ai-insights`, { headers }),
          fetch(`${API_URL}/analytics/skill-breakdown`, { headers }),
          fetch(`${API_URL}/sessions?limit=5`, { headers }),
          fetch(`${API_URL}/analytics/heatmap`, { headers }),
        ]);

        const responses = [
          { label: "total time", response: totalResponse },
          { label: "streak", response: streakResponse },
          { label: "achievements", response: achievementResponse },
          { label: "goals", response: goalsResponse },
          { label: "weekly summary", response: weeklyResponse },
          { label: "AI insights", response: aiInsightsResponse },
          { label: "skill breakdown", response: skillBreakdownResponse },
          { label: "recent sessions", response: recentSessionsResponse },
        ];

        const unauthorized = responses.some(
          ({ response }) => response.status === 401 || response.status === 403,
        );

        if (unauthorized) {
          localStorage.removeItem("token");
          router.push("/login");
          return;
        }

        for (const { label, response } of responses) {
          if (!response.ok) {
            const errorText = await response.text();
            throw new Error(
              `Failed to fetch ${label}: ${response.status} ${errorText}`,
            );
          }
        }

        const [
          totalData,
          streakData,
          achievementData,
          goalsData,
          weeklyDataResponse,
          aiInsightsData,
          skillBreakdownData,
          recentSessionsData,
          heatmapData,
        ] = await Promise.all([
          totalResponse.json(),
          streakResponse.json(),
          achievementResponse.json(),
          goalsResponse.json(),
          weeklyResponse.json(),
          aiInsightsResponse.json(),
          skillBreakdownResponse.json(),
          recentSessionsResponse.json(),
          heatmapResponse.json(),
        ]);

        setTotalHours((totalData.total_minutes / 60).toFixed(1));
        setStreak(streakData.current_streak);
        setAchievementCount(achievementData.achievements.length);
        setAchievements(achievementData.achievements);
        setGoalCount(goalsData.length);
        setWeeklyData(weeklyDataResponse);
        setInsights(aiInsightsData.insights);
        setSkillBreakdown(skillBreakdownData);
        setHeatmapData(heatmapData);
        setRecentSessions(recentSessionsData);
      } catch (error) {
        console.error(error);
      } finally {
        setLoading(false);
      }
    },
    [router],
  );

  useEffect(() => {
    const token = localStorage.getItem("token");

    if (!token) {
      router.push("/login");
    } else {
      queueMicrotask(() => {
        fetchDashboardData(token);
      });
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
    <main className="min-h-screen bg-black text-white flex">
      <Sidebar />
      <div className="flex-1">
        <div className="flex items-center justify-between px-8 py-8 border-b border-gray-800">
          <div>
            <h1 className="text-4xl font-bold">Dashboard</h1>
            <p className="mt-2 text-gray-400">
              Track your learning progress and productivity.
            </p>
          </div>
          <button
            onClick={handleLogout}
            className="rounded-xl border border-gray-700 px-4 py-2 hover:bg-gray-900 transition"
          >
            Logout
          </button>
        </div>

        <section className="p-8 grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-6">
          <DashboardCard
            title="Total Study Hours"
            value={`${totalHours} hrs`}
          />
          <DashboardCard title="Current Streak" value={`${streak} days`} />
          <DashboardCard title="Achievements" value={`${achievementCount}`} />
          <DashboardCard title="Goals" value={`${goalCount}`} />
        </section>

        <section className="px-8 pb-10">
          <WeeklyChart data={weeklyData} />
        </section>

        <section className="px-8 pb-10">
          <AIInsights insights={insights} />
        </section>

        <section className="px-8 pb-10">
          <SkillBreakdown data={skillBreakdown} />
        </section>

        <section className="px-8 pb-10">
          <RecentActivity sessions={recentSessions} />
        </section>

        <section className="px-8 pb-10">
          <AchievementsCard achievements={achievements} />
        </section>

        <section className="px-8 pb-10">
          <StudyHeatmap data={heatmapData} />
        </section>
      </div>
    </main>
  );
}
