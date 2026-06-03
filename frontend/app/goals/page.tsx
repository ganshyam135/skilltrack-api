"use client";

import Sidebar from "@/components/Sidebar";
import { useCallback, useEffect, useState } from "react";
import { useRouter } from "next/navigation";

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

type Goal = {
  id: number;
  title: string;
  target_hours: number;
  start_date: string;
  end_date: string;
};

export default function GoalsPage() {
  const router = useRouter();

  const [title, setTitle] = useState("");
  const [targetHours, setTargetHours] = useState("");

  const [startDate, setStartDate] = useState("");
  const [endDate, setEndDate] = useState("");

  const [goals, setGoals] = useState<Goal[]>([]);

  const [loading, setLoading] = useState(true);

  const fetchGoals = useCallback(async (token: string) => {
    try {
      const response = await fetch(`${API_URL}/goals`, {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });

      const data = await response.json();

      setGoals(data);
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
      queueMicrotask(() => {
        void fetchGoals(token);
      });
    }
  }, [router, fetchGoals]);

  const handleCreateGoal = async () => {
    try {
      const token = localStorage.getItem("token");

      if (!token) return;

      const response = await fetch(`${API_URL}/goals`, {
        method: "POST",

        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },

        body: JSON.stringify({
          title,
          target_hours: Number(targetHours),
          start_date: startDate,
          end_date: endDate,
        }),
      });

      if (response.ok) {
        setTitle("");
        setTargetHours("");
        setStartDate("");
        setEndDate("");

        void fetchGoals(token);
      } else {
        alert("Failed to create goal");
      }
    } catch (error) {
      console.error(error);
    }
  };

  const handleDeleteGoal = async (goalId: number) => {
    try {
      const token = localStorage.getItem("token");

      if (!token) return;

      const response = await fetch(`${API_URL}/goals/${goalId}`, {
        method: "DELETE",
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });

      if (response.ok) {
        void fetchGoals(token);
      } else {
        alert("Failed to delete goal");
      }
    } catch (error) {
      console.error(error);
    }
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
        <div className="px-8 py-8 border-b border-gray-800">
          <h1 className="text-4xl font-bold">Goals</h1>

          <p className="mt-2 text-gray-400">
            Set and manage your learning goals.
          </p>
        </div>

        <section className="p-8">
          <div className="rounded-2xl border border-gray-800 bg-gray-950 p-6">
            <h2 className="text-2xl font-semibold">Create Goal</h2>

            <div className="mt-6 flex flex-col gap-4">
              <input
                type="text"
                placeholder="Goal title"
                value={title}
                onChange={(e) => setTitle(e.target.value)}
                className="rounded-xl border border-gray-700 bg-black px-4 py-3 outline-none focus:border-purple-500"
              />

              <input
                type="number"
                placeholder="Target hours"
                value={targetHours}
                onChange={(e) => setTargetHours(e.target.value)}
                className="rounded-xl border border-gray-700 bg-black px-4 py-3 outline-none focus:border-purple-500"
              />

              <input
                type="date"
                value={startDate}
                onChange={(e) => setStartDate(e.target.value)}
                className="rounded-xl border border-gray-700 bg-black px-4 py-3 outline-none focus:border-purple-500"
              />

              <input
                type="date"
                value={endDate}
                onChange={(e) => setEndDate(e.target.value)}
                className="rounded-xl border border-gray-700 bg-black px-4 py-3 outline-none focus:border-purple-500"
              />

              <button
                onClick={handleCreateGoal}
                className="rounded-xl bg-white text-black py-3 font-medium hover:bg-gray-200 transition"
              >
                Create Goal
              </button>
            </div>
          </div>
        </section>

        <section className="px-8 pb-10">
          <div className="rounded-2xl border border-gray-800 bg-gray-950 p-6">
            <h2 className="text-2xl font-semibold mb-6">Active Goals</h2>

            <div className="flex flex-col gap-4">
              {goals.length === 0 ? (
                <div className="text-center py-12 text-gray-400">
                  No goals yet. Create your first learning goal.
                </div>
              ) : (
                goals.map((goal) => (
                  <div
                    key={goal.id}
                    className="rounded-xl border border-gray-800 p-5"
                  >
                    <div className="flex items-center justify-between">
                      <div>
                        <h3 className="text-xl font-semibold">{goal.title}</h3>

                        <p className="text-purple-400 font-medium mt-1">
                          {goal.target_hours} hrs
                        </p>
                      </div>

                      <button
                        onClick={() => handleDeleteGoal(goal.id)}
                        className="rounded-lg border border-red-500 px-4 py-2 text-red-400 hover:bg-red-500 hover:text-white transition"
                      >
                        Delete
                      </button>
                    </div>

                    <div className="mt-4 flex gap-6 text-sm text-gray-400">
                      <p>
                        Start: {new Date(goal.start_date).toLocaleDateString()}
                      </p>

                      <p>End: {new Date(goal.end_date).toLocaleDateString()}</p>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </section>
      </div>
    </main>
  );
}
