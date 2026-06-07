"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";

// API base URL (use NEXT_PUBLIC_API_URL in environment or fallback to localhost)
const API_URL = process?.env?.NEXT_PUBLIC_API_URL || "http://localhost:8000";

export default function LoginPage() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");

  const [loading, setLoading] = useState(false);
  const router = useRouter();

  const handleLogin = async () => {
    try {
      setLoading(true);

      const formData = new URLSearchParams();

      formData.append("username", username);
      formData.append("password", password);

      const response = await fetch(`${API_URL}/auth/login`, {
        method: "POST",

        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },

        body: formData,
      });

      const data = await response.json();

      if (response.ok) {
        localStorage.setItem("token", data.access_token);

        router.push("/dashboard");
      } else {
        alert("Invalid credentials");
      }
    } catch (error) {
      console.error(error);

      alert("Something went wrong");
    } finally {
      setLoading(false);
    }
  };

  return (
    <main className="min-h-screen bg-black text-white flex items-center justify-center px-6">
      <div className="w-full max-w-md rounded-2xl border border-gray-800 bg-gray-950 p-8">
        <h1 className="text-3xl font-bold">Welcome Back</h1>

        <p className="mt-2 text-gray-400">
          Login to continue your learning journey.
        </p>

        <div className="mt-8 flex flex-col gap-4">
          <input
            type="text"
            placeholder="Username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            className="rounded-xl border border-gray-700 bg-black px-4 py-3 outline-none focus:border-purple-500"
          />

          <input
            type="password"
            placeholder="Password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="rounded-xl border border-gray-700 bg-black px-4 py-3 outline-none focus:border-purple-500"
          />

          <button
            onClick={handleLogin}
            disabled={loading}
            className="rounded-xl bg-white text-black py-3 font-medium hover:bg-gray-200 transition disabled:opacity-50"
          >
            {loading ? "Logging in..." : "Login"}
          </button>
        </div>
      </div>
    </main>
  );
}
