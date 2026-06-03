type DashboardCardProps = {
  title: string;
  value: string;
  detail?: string;
};

export default function DashboardCard({ title, value, detail }: DashboardCardProps) {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-950 p-5 shadow-sm">
      <p className="text-sm font-medium text-slate-400">{title}</p>
      <h2 className="mt-3 text-3xl font-semibold tracking-normal text-white">{value}</h2>
      {detail ? <p className="mt-2 text-sm text-slate-500">{detail}</p> : null}
    </div>
  );
}
