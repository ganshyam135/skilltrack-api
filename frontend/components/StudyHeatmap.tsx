type HeatmapDay = {
  date: string;
  sessions: number;
  total_minutes: number;
};

type StudyHeatmapProps = {
  data: HeatmapDay[];
};

export default function StudyHeatmap({ data }: StudyHeatmapProps) {
  const getIntensity = (minutes: number) => {
    if (minutes === 0) return "bg-slate-900";
    if (minutes < 30) return "bg-teal-950";
    if (minutes < 60) return "bg-teal-800";
    if (minutes < 120) return "bg-teal-600";
    return "bg-teal-400";
  };

  return (
    <div className="min-w-0 rounded-lg border border-slate-800 bg-slate-950 p-5 shadow-sm sm:p-6">
      <h2 className="text-lg font-semibold text-white">Study Consistency</h2>
      <p className="mb-6 mt-1 text-sm text-slate-400">
        Daily sessions and minutes
      </p>

      {data.length === 0 ? (
        <div className="flex h-32 items-center justify-center rounded-lg border border-dashed border-slate-800 text-sm text-slate-500">
          Log study sessions to build your consistency map.
        </div>
      ) : (
        <div className="overflow-x-auto pb-1">
          <div className="grid w-max grid-cols-7 gap-2">
            {data.map((day) => (
              <div
                key={day.date}
                title={`${day.date} - ${day.total_minutes} mins`}
                className={`h-7 w-7 rounded sm:h-8 sm:w-8 ${getIntensity(day.total_minutes)}`}
              />
            ))}
          </div>
        </div>
      )}

      <div className="mt-4 flex flex-wrap items-center gap-3 text-xs text-slate-400">
        <span>Less</span>
        <div className="h-3 w-3 rounded bg-slate-900" />
        <div className="h-3 w-3 rounded bg-teal-950" />
        <div className="h-3 w-3 rounded bg-teal-800" />
        <div className="h-3 w-3 rounded bg-teal-600" />
        <div className="h-3 w-3 rounded bg-teal-400" />
        <span>More</span>
      </div>
    </div>
  );
}
