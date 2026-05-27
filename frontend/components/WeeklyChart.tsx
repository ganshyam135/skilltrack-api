"use client";

import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  CartesianGrid,
} from "recharts";

type WeeklyChartProps = {
  data: {
    date: string;
    minutes: number;
  }[];
};

export default function WeeklyChart({ data }: WeeklyChartProps) {
  return (
    <div className="rounded-2xl border border-gray-800 bg-gray-950 p-6">
      <h2 className="text-2xl font-semibold mb-6">Weekly Study Activity</h2>

      <div className="h-80">
        <ResponsiveContainer width="100%" height="100%">
          <LineChart data={data}>
            <CartesianGrid strokeDasharray="3 3" stroke="#262626" />

            <XAxis dataKey="date" stroke="#a3a3a3" />

            <YAxis stroke="#a3a3a3" />

            <Tooltip />

            <Line
              type="monotone"
              dataKey="minutes"
              stroke="#8b5cf6"
              strokeWidth={3}
            />
          </LineChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
