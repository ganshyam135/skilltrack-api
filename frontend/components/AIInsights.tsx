type AIInsightsProps = {
  insights: string[];
};

export default function AIInsights({ insights }: AIInsightsProps) {
  return (
    <div className="rounded-2xl border border-gray-800 bg-gray-950 p-6">
      <h2 className="text-2xl font-semibold mb-6">AI Insights</h2>

      <div className="space-y-4">
        {insights.length === 0 ? (
          <p className="text-gray-400">No insights available yet.</p>
        ) : (
          insights.map((insight, index) => (
            <div
              key={index}
              className="rounded-xl border border-purple-900 bg-purple-950/20 p-4"
            >
              💡 {insight}
            </div>
          ))
        )}
      </div>
    </div>
  );
}
