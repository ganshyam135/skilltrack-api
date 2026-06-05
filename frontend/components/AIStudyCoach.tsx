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
    <div className="rounded-2xl border border-gray-800 bg-gray-950 p-5 sm:p-6">
      <div className="mb-6 flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <h2 className="text-xl font-semibold sm:text-2xl">AI Study Coach</h2>

        <button
          onClick={onGenerate}
          disabled={loading}
          className="w-full rounded-xl bg-purple-600 px-4 py-2 transition hover:bg-purple-500 disabled:opacity-50 sm:w-auto"
        >
          {loading ? "Generating..." : "Generate Report"}
        </button>
      </div>

      {report ? (
        <div className="whitespace-pre-wrap wrap-break-word leading-7 text-gray-300">
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
