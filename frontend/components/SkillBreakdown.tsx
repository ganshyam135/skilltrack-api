"use client";

import {
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

type SkillBreakdownItem = {
  skill: string;
  minutes: number;
};

type SkillBreakdownProps = {
  data: SkillBreakdownItem[];
};

export default function SkillBreakdown({ data }: SkillBreakdownProps) {
  return (
    <div className="rounded-2xl border border-gray-800 bg-gray-950 p-6">
      <h2 className="text-2xl font-semibold mb-6">Skill Breakdown</h2>

      {data.length === 0 ? (
        <p className="text-gray-400">No skill data available yet.</p>
      ) : (
        <div className="h-80">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={data}>
              <CartesianGrid strokeDasharray="3 3" stroke="#262626" />
              <XAxis dataKey="skill" stroke="#a3a3a3" />
              <YAxis stroke="#a3a3a3" />
              <Tooltip
                formatter={(value) => [`${value} min`, "Study time"]}
              />
              <Bar dataKey="minutes" fill="#22c55e" radius={[8, 8, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}
    </div>
  );
}
