type FeatureCardProps = {
  title: string;
  description: string;
};

export default function FeatureCard({ title, description }: FeatureCardProps) {
  return (
    <div className="rounded-2xl border border-gray-800 bg-gray-950 p-6 hover:border-gray-700 transition">
      <h3 className="text-xl font-semibold">{title}</h3>

      <p className="mt-3 text-gray-400">{description}</p>
    </div>
  );
}
