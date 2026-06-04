type EmptyStateProps = {
  title: string;
  description: string;
  actionLabel: string;
};

export default function EmptyState({
  title,
  description,
  actionLabel,
}: EmptyStateProps) {
  return (
    <div className="rounded-xl border border-dashed border-gray-800 bg-black/30 px-6 py-12 text-center">
      <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-lg border border-gray-800 bg-gray-950 text-lg font-semibold text-purple-300">
        +
      </div>

      <h3 className="mt-5 text-xl font-semibold text-white">{title}</h3>

      <p className="mx-auto mt-2 max-w-md text-sm leading-6 text-gray-400">
        {description}
      </p>

      <p className="mt-5 text-sm font-medium text-purple-300">{actionLabel}</p>
    </div>
  );
}
