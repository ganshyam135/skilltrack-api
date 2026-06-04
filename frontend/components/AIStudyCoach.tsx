"use client";

type AIStudyCoachProps = {
  report: string;
  loading: boolean;
  onGenerate: () => void;
};

export default function AIStudyCoach({
  report,
  loading,
  onGenerate,
}: AIStudyCoachProps) {
  return (
    <div className="rounded-2xl border border-gray-800 bg-gray-950 p-6">
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-2xl font-semibold">🤖 AI Study Coach</h2>

        <button
          onClick={onGenerate}
          disabled={loading}
          className="rounded-xl bg-purple-600 px-4 py-2 hover:bg-purple-500 transition disabled:opacity-50"
        >
          {loading ? "Generating..." : "Generate Report"}
        </button>
      </div>

      {report ? (
        <div className="whitespace-pre-wrap text-gray-300 leading-7">
          {report}
        </div>
      ) : (
        <p className="text-gray-500">
          Generate a personalized learning report using AI.
        </p>
      )}
    </div>
  );
}
