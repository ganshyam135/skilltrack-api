import Navbar from "@/components/Navbar";
import FeatureCard from "@/components/FeatureCard";

export default function Home() {
  return (
    <main className="min-h-screen bg-black text-white">
      <Navbar />

      <section className="flex flex-col items-center justify-center text-center px-6 py-28">
        <h1 className="text-6xl font-bold tracking-tight max-w-4xl">
          Track Your Learning
          <span className="bg-linear-to-r from-purple-400 to-blue-500 bg-clip-text text-transparent">
            {" "}
            Like Never Before
          </span>
        </h1>

        <p className="mt-6 text-lg text-gray-400 max-w-2xl">
          SkillTrack helps you analyze study habits, maintain streaks, track
          goals, and gain AI-powered insights into your learning journey.
        </p>

        <div className="mt-10 flex gap-4">
          <button className="rounded-xl bg-white text-black px-6 py-3 font-medium hover:bg-gray-200 transition">
            Get Started
          </button>

          <button className="rounded-xl border border-gray-700 px-6 py-3 font-medium hover:bg-gray-900 transition">
            Learn More
          </button>
        </div>
      </section>

      <section className="grid grid-cols-1 md:grid-cols-3 gap-6 px-8 pb-24">
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
