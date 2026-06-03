type AIInsightsProps = {
  insights: string[];
};

export default function AIInsights({ insights }: AIInsightsProps) {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-950 p-6 shadow-sm">
      <div className="mb-6 flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-lg font-semibold text-white">Learning Insights</h2>
          <p className="mt-1 text-sm text-slate-400">
            Rules-based preview for future recommendations
          </p>
        </div>
        <span className="rounded-md border border-teal-900 bg-teal-950 px-2.5 py-1 text-xs font-medium text-teal-200">
          Preview
        </span>
      </div>

      <div className="space-y-4">
        {insights.length === 0 ? (
          <p className="text-sm text-slate-400">No insights available yet.</p>
        ) : (
          insights.map((insight, index) => (
            <div
              key={index}
              className="rounded-lg border border-slate-800 bg-slate-900/70 p-4 text-sm text-slate-200"
            >
              {insight}
            </div>
          ))
        )}
      </div>
    </div>
  );
}
