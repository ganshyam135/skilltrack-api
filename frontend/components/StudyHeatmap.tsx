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
    if (minutes === 0) return "bg-gray-900";
    if (minutes < 30) return "bg-green-900";
    if (minutes < 60) return "bg-green-700";
    if (minutes < 120) return "bg-green-500";
    return "bg-green-400";
  };

  return (
    <div className="rounded-2xl border border-gray-800 bg-gray-950 p-6">
      <h2 className="text-2xl font-semibold mb-6">Study Consistency</h2>

      <div className="grid grid-cols-7 gap-2">
        {data.map((day) => (
          <div
            key={day.date}
            title={`${day.date} - ${day.total_minutes} mins`}
            className={`
              h-8
              w-8
              rounded
              ${getIntensity(day.total_minutes)}
            `}
          />
        ))}
      </div>

      <div className="mt-4 flex items-center gap-3 text-xs text-gray-400">
        <span>Less</span>

        <div className="h-3 w-3 rounded bg-gray-900" />
        <div className="h-3 w-3 rounded bg-green-900" />
        <div className="h-3 w-3 rounded bg-green-700" />
        <div className="h-3 w-3 rounded bg-green-500" />
        <div className="h-3 w-3 rounded bg-green-400" />

        <span>More</span>
      </div>
    </div>
  );
}
