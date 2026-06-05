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

type SkillBreakdownProps = {
  data: {
    skill: string;
    minutes: number;
  }[];
};

export default function SkillBreakdown({ data }: SkillBreakdownProps) {
  return (
    <div className="min-w-0 rounded-lg border border-slate-800 bg-slate-950 p-5 shadow-sm sm:p-6">
      <h2 className="mb-1 text-lg font-semibold text-white">Skill Breakdown</h2>
      <p className="mb-6 text-sm text-slate-400">
        Where your study time is going
      </p>

      <div className="h-72 overflow-x-auto sm:h-80">
        {data.length === 0 ? (
          <div className="flex h-full items-center justify-center rounded-lg border border-dashed border-slate-800 text-sm text-slate-500">
            Add sessions linked to skills to see a breakdown.
          </div>
        ) : (
          <div className="h-full min-w-130 sm:min-w-0">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={data} margin={{ left: -8, right: 12 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis
                  dataKey="skill"
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
                <Bar dataKey="minutes" fill="#f59e0b" radius={[6, 6, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        )}
      </div>
    </div>
  );
}
