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

type Skill = {
  id: number;
  name: string;
};

type Topic = {
  id: number;
  title: string;
  skill_id: number;
};

export default function SessionsPage() {
  const router = useRouter();

  const [duration, setDuration] = useState("");
  const [notes, setNotes] = useState("");
  const [skillId, setSkillId] = useState("");
  const [topicId, setTopicId] = useState("");

  const [sessions, setSessions] = useState<Session[]>([]);
  const [skills, setSkills] = useState<Skill[]>([]);
  const [topics, setTopics] = useState<Topic[]>([]);

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
    }
  }, []);

  const fetchSkills = useCallback(async (token: string) => {
    try {
      const response = await fetch(`${API_URL}/skills`, {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });

      const data = await response.json();

      setSkills(data);
    } catch (error) {
      console.error(error);
    }
  }, []);

  const fetchTopics = useCallback(async (token: string) => {
    try {
      const response = await fetch(`${API_URL}/topics`, {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });

      const data = await response.json();

      setTopics(data);
    } catch (error) {
      console.error(error);
    }
  }, []);

  const fetchPageData = useCallback(
    async (token: string) => {
      try {
        await Promise.all([
          fetchSessions(token),
          fetchSkills(token),
          fetchTopics(token),
        ]);
      } finally {
        setLoading(false);
      }
    },
    [fetchSessions, fetchSkills, fetchTopics]
  );

  useEffect(() => {
    const token = localStorage.getItem("token");

    if (!token) {
      router.push("/login");
    } else {
      fetchPageData(token);
    }
  }, [router, fetchPageData]);

  const handleCreateSession = async () => {
    try {
      const token = localStorage.getItem("token");

      if (!token) return;
      if (!duration || !skillId || !topicId) {
        alert("Please select a skill, topic, and duration");
        return;
      }

      const response = await fetch(`${API_URL}/sessions`, {
        method: "POST",

        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },

        body: JSON.stringify({
          duration: Number(duration),
          notes,
          skill_id: Number(skillId),
          topic_id: Number(topicId),
        }),
      });

      if (response.ok) {
        setDuration("");
        setNotes("");
        setSkillId("");
        setTopicId("");

        fetchSessions(token);
      } else {
        alert("Failed to create session");
      }
    } catch (error) {
      console.error(error);
    }
  };

  const filteredTopics = skillId
    ? topics.filter((topic) => topic.skill_id === Number(skillId))
    : topics;

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
              <select
                value={skillId}
                onChange={(e) => {
                  setSkillId(e.target.value);
                  setTopicId("");
                }}
                className="rounded-xl border border-gray-700 bg-black px-4 py-3 outline-none focus:border-purple-500"
              >
                <option value="">Select skill</option>
                {skills.map((skill) => (
                  <option key={skill.id} value={skill.id}>
                    {skill.name}
                  </option>
                ))}
              </select>

              <select
                value={topicId}
                onChange={(e) => setTopicId(e.target.value)}
                className="rounded-xl border border-gray-700 bg-black px-4 py-3 outline-none focus:border-purple-500"
              >
                <option value="">Select topic</option>
                {filteredTopics.map((topic) => (
                  <option key={topic.id} value={topic.id}>
                    {topic.title}
                  </option>
                ))}
              </select>

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
                </div>
              ))}
            </div>
          </div>
        </section>
      </div>
    </main>
  );
}
