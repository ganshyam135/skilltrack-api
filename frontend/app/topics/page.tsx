"use client";

import Sidebar from "@/components/Sidebar";
import EmptyState from "@/components/EmptyState";
import { useCallback, useEffect, useState } from "react";
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

export default function TopicsPage() {
  const router = useRouter();

  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");

  const [selectedSkill, setSelectedSkill] = useState("");

  const [skills, setSkills] = useState<Skill[]>([]);
  const [topics, setTopics] = useState<Topic[]>([]);

  const [loading, setLoading] = useState(true);

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

  const fetchInitialData = useCallback(
    async (token: string) => {
      try {
        await Promise.all([fetchSkills(token), fetchTopics(token)]);
      } catch (error) {
        console.error(error);
      } finally {
        setLoading(false);
      }
    },
    [fetchSkills, fetchTopics],
  );

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

  const handleCreateTopic = async () => {
    try {
      const token = localStorage.getItem("token");

      if (!token) return;

      const response = await fetch(`${API_URL}/topics`, {
        method: "POST",

        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },

        body: JSON.stringify({
          title,
          description,
          skill_id: Number(selectedSkill),
        }),
      });

      if (response.ok) {
        setTitle("");
        setDescription("");
        setSelectedSkill("");

        void fetchTopics(token);
      } else {
        alert("Failed to create topic");
      }
    } catch (error) {
      console.error(error);
    }
  };

  const getSkillName = (skillId: number) => {
    const skill = skills.find((skill) => skill.id === skillId);

    return skill ? skill.name : "Unknown Skill";
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
          <h1 className="text-4xl font-bold">Topics</h1>

          <p className="mt-2 text-gray-400">
            Manage learning topics under your skills.
          </p>
        </div>

        <section className="p-8">
          <div className="rounded-2xl border border-gray-800 bg-gray-950 p-6">
            <h2 className="text-2xl font-semibold">Create Topic</h2>

            <div className="mt-6 flex flex-col gap-4">
              <input
                type="text"
                placeholder="Topic title"
                value={title}
                onChange={(e) => setTitle(e.target.value)}
                className="rounded-xl border border-gray-700 bg-black px-4 py-3 outline-none focus:border-purple-500"
              />

              <textarea
                placeholder="Description"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                className="rounded-xl border border-gray-700 bg-black px-4 py-3 outline-none focus:border-purple-500"
              />

              <select
                value={selectedSkill}
                onChange={(e) => setSelectedSkill(e.target.value)}
                className="rounded-xl border border-gray-700 bg-black px-4 py-3 outline-none focus:border-purple-500"
              >
                <option value="">Select Skill</option>

                {skills.map((skill) => (
                  <option key={skill.id} value={skill.id}>
                    {skill.name}
                  </option>
                ))}
              </select>

              <button
                onClick={handleCreateTopic}
                className="rounded-xl bg-white text-black py-3 font-medium hover:bg-gray-200 transition"
              >
                Create Topic
              </button>
            </div>
          </div>
        </section>

        <section className="px-8 pb-10">
          <div className="rounded-2xl border border-gray-800 bg-gray-950 p-6">
            <h2 className="text-2xl font-semibold mb-6">Your Topics</h2>

            {topics.length === 0 ? (
              <EmptyState
                title="No topics created yet"
                description="Topics help break each skill into focused areas so your sessions become easier to track."
                actionLabel="Create your first topic using the form above."
              />
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
                {topics.map((topic) => (
                  <div
                    key={topic.id}
                    className="rounded-xl border border-gray-800 p-5"
                  >
                    <h3 className="text-2xl font-semibold">{topic.title}</h3>

                    <p className="mt-3 text-gray-400">{topic.description}</p>

                    <p className="mt-4 text-sm text-purple-400">
                      {getSkillName(topic.skill_id)}
                    </p>
                  </div>
                ))}
              </div>
            )}
          </div>
        </section>
      </div>
    </main>
  );
}
