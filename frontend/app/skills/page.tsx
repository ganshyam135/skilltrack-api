"use client";

import Sidebar from "@/components/Sidebar";
import EmptyState from "@/components/EmptyState";
import { useCallback, useEffect, useState } from "react";
import { useRouter } from "next/navigation";

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

type Skill = {
  id: number;
  name: string;
  description: string;
};

export default function SkillsPage() {
  const router = useRouter();

  const [name, setName] = useState("");
  const [description, setDescription] = useState("");

  const [skills, setSkills] = useState<Skill[]>([]);

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
        fetchSkills(token);
      });
    }
  }, [router, fetchSkills]);

  const handleCreateSkill = async () => {
    try {
      const token = localStorage.getItem("token");

      if (!token) return;

      const response = await fetch(`${API_URL}/skills`, {
        method: "POST",

        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },

        body: JSON.stringify({
          name,
          description,
        }),
      });

      if (response.ok) {
        setName("");
        setDescription("");

        fetchSkills(token);
      } else {
        alert("Failed to create skill");
      }
    } catch (error) {
      console.error(error);
    }
  };

  const handleDeleteSkill = async (skillId: number) => {
    try {
      const token = localStorage.getItem("token");

      if (!token) return;

      const response = await fetch(`${API_URL}/skills/${skillId}`, {
        method: "DELETE",

        headers: {
          Authorization: `Bearer ${token}`,
        },
      });

      if (response.ok) {
        fetchSkills(token);
      } else {
        const errorData = await response.json();
        console.error(errorData);
        alert("Failed to delete skill");
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
          <h1 className="text-4xl font-bold">Skills</h1>

          <p className="mt-2 text-gray-400">
            Organize and track your learning skills.
          </p>
        </div>

        <section className="p-8">
          <div className="rounded-2xl border border-gray-800 bg-gray-950 p-6">
            <h2 className="text-2xl font-semibold">Create Skill</h2>

            <div className="mt-6 flex flex-col gap-4">
              <input
                type="text"
                placeholder="Skill name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                className="rounded-xl border border-gray-700 bg-black px-4 py-3 outline-none focus:border-purple-500"
              />

              <textarea
                placeholder="Description"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                className="rounded-xl border border-gray-700 bg-black px-4 py-3 outline-none focus:border-purple-500"
              />

              <button
                onClick={handleCreateSkill}
                className="rounded-xl bg-white text-black py-3 font-medium hover:bg-gray-200 transition"
              >
                Create Skill
              </button>
            </div>
          </div>
        </section>

        <section className="px-8 pb-10">
          <div className="rounded-2xl border border-gray-800 bg-gray-950 p-6">
            <h2 className="text-2xl font-semibold mb-6">Your Skills</h2>

            {skills.length === 0 ? (
              <EmptyState
                title="No skills added yet"
                description="Create your first skill to start organizing topics, sessions, goals, and progress around it."
                actionLabel="Use the Create Skill form above to begin."
              />
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
                {skills.map((skill) => (
                  <div
                    key={skill.id}
                    className="rounded-xl border border-gray-800 p-5 flex flex-col justify-between"
                  >
                    <div>
                      <h3 className="text-2xl font-semibold">{skill.name}</h3>

                      <p className="mt-3 text-gray-400">{skill.description}</p>
                    </div>

                    <button
                      onClick={() => handleDeleteSkill(skill.id)}
                      className="mt-6 rounded-xl border border-red-500 text-red-400 px-4 py-2 hover:bg-red-500 hover:text-white transition"
                    >
                      Delete
                    </button>
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
