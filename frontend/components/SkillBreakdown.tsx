"use client";

import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
} from "recharts";

type SkillBreakdownProps = {
  data: {
    skill: string;
    minutes: number;
  }[];
};

export default function SkillBreakdown({
  data,
}: SkillBreakdownProps) {
  return (
    <div className="rounded-2xl border border-gray-800 bg-gray-950 p-6">

      <h2 className="text-2xl font-semibold mb-6">
        Skill Breakdown
      </h2>

      <div className="h-80">

        <ResponsiveContainer
          width="100%"
          height="100%"
        >

          <BarChart data={data}>

            <CartesianGrid
              strokeDasharray="3 3"
              stroke="#262626"
            />

            <XAxis
              dataKey="skill"
              stroke="#a3a3a3"
            />

            <YAxis stroke="#a3a3a3" />

            <Tooltip />

            <Bar
              dataKey="minutes"
              fill="#8b5cf6"
            />

          </BarChart>

        </ResponsiveContainer>

      </div>

    </div>
  );
}