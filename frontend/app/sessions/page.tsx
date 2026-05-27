"use client";

import Sidebar from "@/components/Sidebar";
import { useCallback, useEffect, useState } from "react";
import { useRouter } from "next/navigation";

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

type Session = {
  id: number;
  duration: number;
  notes: string;
  created_at: string;
};

export default function SessionsPage() {
  const router = useRouter();

  const [duration, setDuration] = useState("");
  const [notes, setNotes] = useState("");

  const [sessions, setSessions] = useState<Session[]>([]);

  const [loading, setLoading] = useState(true);

  const fetchSessions = useCallback(async (token: string) => {
    try {
      const response = await fetch(`${API_URL}/sessions`, {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });

      const data = await response.json();

      setSessions(data);
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
        fetchSessions(token);
      });
    }
  }, [router, fetchSessions]);

  const handleCreateSession = async () => {
    try {
      const token = localStorage.getItem("token");

      if (!token) return;

      const response = await fetch(`${API_URL}/sessions`, {
        method: "POST",

        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },

        body: JSON.stringify({
          duration: Number(duration),
          notes,
        }),
      });

      if (response.ok) {
        setDuration("");
        setNotes("");

        fetchSessions(token);
      } else {
        alert("Failed to create session");
      }
    } catch (error) {
      console.error(error);
    }
  };

  const handleDeleteSession = async (sessionId: number) => {
    try {
      const token = localStorage.getItem("token");

      if (!token) return;

      const response = await fetch(`${API_URL}/sessions/${sessionId}`, {
        method: "DELETE",

        headers: {
          Authorization: `Bearer ${token}`,
        },
      });

      if (response.ok) {
        fetchSessions(token);
      } else {
        alert("Failed to delete session");
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
          <h1 className="text-4xl font-bold">Study Sessions</h1>

          <p className="mt-2 text-gray-400">
            Track and manage your learning sessions.
          </p>
        </div>

        <section className="p-8">
          <div className="rounded-2xl border border-gray-800 bg-gray-950 p-6">
            <h2 className="text-2xl font-semibold">Add Study Session</h2>

            <div className="mt-6 flex flex-col gap-4">
              <input
                type="number"
                placeholder="Duration in minutes"
                value={duration}
                onChange={(e) => setDuration(e.target.value)}
                className="rounded-xl border border-gray-700 bg-black px-4 py-3 outline-none focus:border-purple-500"
              />

              <textarea
                placeholder="Notes"
                value={notes}
                onChange={(e) => setNotes(e.target.value)}
                className="rounded-xl border border-gray-700 bg-black px-4 py-3 outline-none focus:border-purple-500"
              />

              <button
                onClick={handleCreateSession}
                className="rounded-xl bg-white text-black py-3 font-medium hover:bg-gray-200 transition"
              >
                Add Session
              </button>
            </div>
          </div>
        </section>

        <section className="px-8 pb-10">
          <div className="rounded-2xl border border-gray-800 bg-gray-950 p-6">
            <h2 className="text-2xl font-semibold mb-6">Session History</h2>

            <div className="flex flex-col gap-4">
              {sessions.map((session) => (
                <div
                  key={session.id}
                  className="rounded-xl border border-gray-800 p-4"
                >
                  <div className="flex items-center justify-between">
                    <h3 className="text-xl font-semibold">
                      {session.duration} minutes
                    </h3>

                    <p className="text-sm text-gray-500">
                      {new Date(session.created_at).toLocaleDateString()}
                    </p>
                  </div>

                  <p className="mt-3 text-gray-400">{session.notes}</p>

                  <button
                    onClick={() => handleDeleteSession(session.id)}
                    className="mt-4 rounded-xl border border-red-500 text-red-400 px-4 py-2 hover:bg-red-500 hover:text-white transition"
                  >
                    Delete
                  </button>
                </div>
              ))}
            </div>
          </div>
        </section>
      </div>
    </main>
  );
}
