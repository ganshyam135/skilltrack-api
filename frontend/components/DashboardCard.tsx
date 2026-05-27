type DashboardCardProps = {
  title: string;
  value: string;
};

export default function DashboardCard({ title, value }: DashboardCardProps) {
  return (
    <div className="rounded-2xl border border-gray-800 bg-gray-950 p-6">
      <p className="text-gray-400">{title}</p>

      <h2 className="mt-3 text-4xl font-bold">{value}</h2>
    </div>
  );
}
