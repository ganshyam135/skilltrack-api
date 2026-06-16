"use client";

import { useState } from "react";

// API base URL temporarily hardcoded for production deployment debugging
const API_URL = "https://skilltrack-jcjy.onrender.com";

export default function SignupPage() {
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");

  const [loading, setLoading] = useState(false);

  const handleSignup = async () => {
    try {
      setLoading(true);

      const response = await fetch(`${API_URL}/auth/register`, {
        method: "POST",

        headers: {
          "Content-Type": "application/json",
        },

        body: JSON.stringify({
          username,
          email,
          password,
        }),
      });

      if (response.ok) {
        alert("Account created successfully!");

        setUsername("");
        setEmail("");
        setPassword("");
      } else {
        const errorData = await response.json().catch(() => null);
        alert(errorData?.detail || "Signup failed");
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
        <h1 className="text-3xl font-bold">Create Account</h1>

        <p className="mt-2 text-gray-400">
          Start tracking your learning journey today.
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
            type="email"
            placeholder="Email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
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
            onClick={handleSignup}
            disabled={loading}
            className="rounded-xl bg-white text-black py-3 font-medium hover:bg-gray-200 transition disabled:opacity-50"
          >
            {loading ? "Creating Account..." : "Create Account"}
          </button>
        </div>
      </div>
    </main>
  );
}
