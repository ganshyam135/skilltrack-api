"use client";

import Navbar from "@/components/Navbar";
import FeatureCard from "@/components/FeatureCard";

import { useRouter } from "next/navigation";

export default function Home() {
  const router = useRouter();

  const handleGetStarted = () => {
    const token = localStorage.getItem("token");

    if (token) {
      router.push("/dashboard");
    } else {
      router.push("/login");
    }
  };

  const handleLearnMore = () => {
    const featuresSection = document.getElementById("features");

    if (featuresSection) {
      featuresSection.scrollIntoView({
        behavior: "smooth",
      });
    }
  };

  return (
    <main className="min-h-screen bg-black text-white">
      <Navbar />

      <section className="flex flex-col items-center justify-center text-center px-6 py-32">
        <div className="max-w-5xl">
          <h1 className="text-6xl md:text-7xl font-bold tracking-tight leading-tight">
            Track Your Learning
            <span className="bg-gradient-to-r from-purple-400 to-blue-500 bg-clip-text text-transparent">
              {" "}
              Like Never Before
            </span>
          </h1>

          <p className="mt-8 text-lg md:text-xl text-gray-400 max-w-3xl mx-auto leading-relaxed">
            SkillTrack helps you analyze study habits, maintain streaks, track
            goals, and gain AI-powered insights into your learning journey.
          </p>

          <div className="mt-12 flex flex-col sm:flex-row items-center justify-center gap-4">
            <button
              onClick={handleGetStarted}
              className="rounded-xl bg-white text-black px-8 py-4 font-semibold hover:bg-gray-200 transition"
            >
              Get Started
            </button>

            <button
              onClick={handleLearnMore}
              className="rounded-xl border border-gray-700 px-8 py-4 font-semibold hover:bg-gray-900 transition"
            >
              Learn More
            </button>
          </div>
        </div>
      </section>

      <section
        id="features"
        className="grid grid-cols-1 md:grid-cols-3 gap-6 px-8 pb-24"
      >
        <FeatureCard
          title="Analytics Dashboard"
          description="Visualize your study habits with powerful charts and insights."
        />

        <FeatureCard
          title="Goal Tracking"
          description="Track learning goals and monitor progress over time."
        />

        <FeatureCard
          title="AI Insights"
          description="Receive intelligent recommendations powered by AI."
        />
      </section>
    </main>
  );
}
