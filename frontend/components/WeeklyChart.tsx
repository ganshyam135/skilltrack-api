"use client";

import {
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

type WeeklyChartProps = {
  data: {
    date: string;
    minutes: number;
  }[];
};

export default function WeeklyChart({ data }: WeeklyChartProps) {
  return (
    <div className="min-w-0 rounded-lg border border-slate-800 bg-slate-950 p-5 shadow-sm sm:p-6">
      <div className="mb-6">
        <h2 className="text-lg font-semibold text-white">Study Activity</h2>
        <p className="mt-1 text-sm text-slate-400">Minutes logged by day</p>
      </div>

      <div className="h-72 overflow-x-auto sm:h-80">
        {data.length === 0 ? (
          <div className="flex h-full items-center justify-center rounded-lg border border-dashed border-slate-800 text-sm text-slate-500">
            No study activity yet.
          </div>
        ) : (
          <div className="h-full min-w-130 sm:min-w-0">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={data} margin={{ left: -8, right: 12 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis
                  dataKey="date"
                  stroke="#94a3b8"
                  tick={{ fontSize: 12 }}
                />
                <YAxis stroke="#94a3b8" tick={{ fontSize: 12 }} width={42} />
                <Tooltip
                  contentStyle={{
                    background: "#020617",
                    border: "1px solid #1e293b",
                    borderRadius: "8px",
                    color: "#f8fafc",
                  }}
                />
                <Line
                  type="monotone"
                  dataKey="minutes"
                  stroke="#14b8a6"
                  strokeWidth={3}
                  dot={{ r: 3 }}
                  activeDot={{ r: 5 }}
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
        )}
      </div>
    </div>
  );
}
