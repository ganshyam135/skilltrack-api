"use client";

import Sidebar from "@/components/Sidebar";

import { useCallback, useEffect, useMemo, useState } from "react";

import { useRouter } from "next/navigation";

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

type Skill = {
  id: number;
  name: string;
};

type Topic = {
  id: number;
  title: string;
  description: string;
  skill_id: number;
};

type Session = {
  id: number;
  duration: number;
  notes: string;
  created_at: string;
  skill_id: number;
  topics_id: number;
};

export default function SessionsPage() {
  const router = useRouter();

  const [duration, setDuration] = useState("");

  const [notes, setNotes] = useState("");

  const [selectedSkill, setSelectedSkill] = useState("");

  const [selectedTopic, setSelectedTopic] = useState("");

  const [newTopicTitle, setNewTopicTitle] = useState("");

  const [newTopicDescription, setNewTopicDescription] = useState("");

  const [skills, setSkills] = useState<Skill[]>([]);

  const [topics, setTopics] = useState<Topic[]>([]);

  const [sessions, setSessions] = useState<Session[]>([]);

  const [loading, setLoading] = useState(true);

  const fetchSkills = useCallback(async (token: string) => {
    const response = await fetch(`${API_URL}/skills`, {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    const data = await response.json();

    setSkills(data);
  }, []);

  const fetchTopics = useCallback(async (token: string) => {
    const response = await fetch(`${API_URL}/topics`, {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    const data = await response.json();

    setTopics(data);
  }, []);

  const fetchSessions = useCallback(async (token: string) => {
    const response = await fetch(`${API_URL}/sessions`, {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    const data = await response.json();

    setSessions(data);
  }, []);

  const fetchInitialData = useCallback(async (token: string) => {
    try {
      await Promise.all([
        fetchSkills(token),
        fetchTopics(token),
        fetchSessions(token),
      ]);
    } catch (error) {
      console.error(error);
    } finally {
      setLoading(false);
    }
  }, [fetchSessions, fetchSkills, fetchTopics]);

  useEffect(() => {
    const token = localStorage.getItem("token");

    if (!token) {
      router.push("/login");
    } else {
      queueMicrotask(() => {
        void fetchInitialData(token);
      });
    }
  }, [router, fetchInitialData]);

  const filteredTopics = useMemo(() => {
    return topics.filter((topic) => topic.skill_id === Number(selectedSkill));
  }, [topics, selectedSkill]);

  const handleCreateTopic = async () => {
    try {
      const token = localStorage.getItem("token");

      if (!token || !selectedSkill) return;

      const response = await fetch(`${API_URL}/topics/`, {
        method: "POST",

        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },

        body: JSON.stringify({
          title: newTopicTitle,
          description: newTopicDescription,
          skill_id: Number(selectedSkill),
        }),
      });

      if (response.ok) {
        setNewTopicTitle("");

        setNewTopicDescription("");

        void fetchTopics(token);
      } else {
        alert("Failed to create topic");
      }
    } catch (error) {
      console.error(error);
    }
  };

  const handleCreateSession = async () => {
    try {
      const token = localStorage.getItem("token");

      if (!token) return;

      const response = await fetch(`${API_URL}/sessions/`, {
        method: "POST",

        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },

        body: JSON.stringify({
          duration: Number(duration),
          notes,
          skill_id: Number(selectedSkill),
          topic_id: Number(selectedTopic),
        }),
      });

      if (response.ok) {
        setDuration("");

        setNotes("");

        setSelectedTopic("");

        void fetchSessions(token);
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
        void fetchSessions(token);
      } else {
        alert("Failed to delete session");
      }
    } catch (error) {
      console.error(error);
    }
  };

  const getSkillName = (skillId: number) => {
    const skill = skills.find((skill) => skill.id === skillId);

    return skill ? skill.name : "Unknown Skill";
  };

  const getTopicName = (topicId: number) => {
    const topic = topics.find((topic) => topic.id === topicId);

    return topic ? topic.title : "Unknown Topic";
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
            Track your learning sessions and progress.
          </p>
        </div>

        <section className="p-8 grid grid-cols-1 xl:grid-cols-2 gap-8">
          <div className="rounded-2xl border border-gray-800 bg-gray-950 p-6">
            <h2 className="text-2xl font-semibold">Add Study Session</h2>

            <div className="mt-6 flex flex-col gap-4">
              <select
                value={selectedSkill}
                onChange={(e) => setSelectedSkill(e.target.value)}
                className="rounded-xl border border-gray-700 bg-black px-4 py-3"
              >
                <option value="">Select Skill</option>

                {skills.map((skill) => (
                  <option key={skill.id} value={skill.id}>
                    {skill.name}
                  </option>
                ))}
              </select>

              <select
                value={selectedTopic}
                onChange={(e) => setSelectedTopic(e.target.value)}
                className="rounded-xl border border-gray-700 bg-black px-4 py-3"
              >
                <option value="">Select Topic</option>

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
                className="rounded-xl border border-gray-700 bg-black px-4 py-3"
              />

              <textarea
                placeholder="Session notes"
                value={notes}
                onChange={(e) => setNotes(e.target.value)}
                className="rounded-xl border border-gray-700 bg-black px-4 py-3"
              />

              <button
                onClick={handleCreateSession}
                className="rounded-xl bg-white text-black py-3 font-semibold hover:bg-gray-200 transition"
              >
                Add Session
              </button>
            </div>
          </div>

          <div className="rounded-2xl border border-gray-800 bg-gray-950 p-6">
            <h2 className="text-2xl font-semibold">Quick Create Topic</h2>

            <div className="mt-6 flex flex-col gap-4">
              <input
                type="text"
                placeholder="Topic title"
                value={newTopicTitle}
                onChange={(e) => setNewTopicTitle(e.target.value)}
                className="rounded-xl border border-gray-700 bg-black px-4 py-3"
              />

              <textarea
                placeholder="Topic description"
                value={newTopicDescription}
                onChange={(e) => setNewTopicDescription(e.target.value)}
                className="rounded-xl border border-gray-700 bg-black px-4 py-3"
              />

              <button
                onClick={handleCreateTopic}
                className="rounded-xl border border-purple-500 text-purple-400 py-3 font-semibold hover:bg-purple-500 hover:text-white transition"
              >
                Create Topic
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
                  className="rounded-xl border border-gray-800 p-5"
                >
                  <div className="flex items-start justify-between">
                    <div>
                      <h3 className="text-2xl font-semibold">
                        {session.duration} mins
                      </h3>

                      <p className="mt-2 text-purple-400">
                        {getSkillName(session.skill_id)}
                      </p>

                      <p className="text-blue-400 text-sm mt-1">
                        {getTopicName(session.topics_id)}
                      </p>
                    </div>

                    <button
                      onClick={() => handleDeleteSession(session.id)}
                      className="rounded-lg border border-red-500 px-4 py-2 text-red-400 hover:bg-red-500 hover:text-white transition"
                    >
                      Delete
                    </button>
                  </div>

                  <p className="mt-4 text-gray-400">{session.notes}</p>

                  <p className="mt-4 text-sm text-gray-500">
                    {new Date(session.created_at).toLocaleDateString()}
                  </p>
                </div>
              ))}
            </div>
          </div>
        </section>
      </div>
    </main>
  );
}
