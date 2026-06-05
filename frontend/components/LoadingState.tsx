type LoadingStateProps = {
  title?: string;
  description?: string;
  variant?: "dashboard" | "management";
};

function SkeletonBlock({ className }: { className: string }) {
  return (
    <div className={`animate-pulse rounded-lg bg-slate-800/80 ${className}`} />
  );
}

function DashboardSkeleton() {
  return (
    <div className="w-full max-w-6xl space-y-6">
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
        {Array.from({ length: 4 }).map((_, index) => (
          <div
            key={index}
            className="rounded-lg border border-slate-800 bg-slate-950 p-5"
          >
            <SkeletonBlock className="h-4 w-28" />
            <SkeletonBlock className="mt-4 h-8 w-24" />
            <SkeletonBlock className="mt-3 h-3 w-32" />
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-[minmax(0,1.5fr)_minmax(360px,1fr)]">
        <div className="rounded-lg border border-slate-800 bg-slate-950 p-6">
          <SkeletonBlock className="h-5 w-36" />
          <SkeletonBlock className="mt-8 h-64 w-full" />
        </div>
        <div className="rounded-lg border border-slate-800 bg-slate-950 p-6">
          <SkeletonBlock className="h-5 w-40" />
          <div className="mt-8 space-y-4">
            <SkeletonBlock className="h-16 w-full" />
            <SkeletonBlock className="h-16 w-full" />
            <SkeletonBlock className="h-16 w-full" />
          </div>
        </div>
      </div>
    </div>
  );
}

function ManagementSkeleton() {
  return (
    <div className="grid w-full max-w-6xl grid-cols-1 gap-6 xl:grid-cols-[minmax(320px,0.8fr)_minmax(0,1.2fr)]">
      <div className="rounded-lg border border-slate-800 bg-slate-950 p-6">
        <SkeletonBlock className="h-6 w-32" />
        <div className="mt-6 space-y-4">
          <SkeletonBlock className="h-12 w-full" />
          <SkeletonBlock className="h-24 w-full" />
          <SkeletonBlock className="h-12 w-full" />
        </div>
      </div>

      <div className="rounded-lg border border-slate-800 bg-slate-950 p-6">
        <SkeletonBlock className="h-6 w-40" />
        <div className="mt-6 grid grid-cols-1 gap-4 md:grid-cols-2">
          {Array.from({ length: 4 }).map((_, index) => (
            <div key={index} className="rounded-lg border border-slate-800 p-5">
              <SkeletonBlock className="h-5 w-32" />
              <SkeletonBlock className="mt-4 h-4 w-full" />
              <SkeletonBlock className="mt-3 h-4 w-2/3" />
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

export default function LoadingState({
  title = "Loading workspace",
  description = "Preparing your SkillTrack data...",
  variant = "management",
}: LoadingStateProps) {
  return (
    <main className="min-h-screen bg-slate-950 px-5 py-8 text-white sm:px-8">
      <div className="mx-auto w-full max-w-6xl">
        <div className="mb-8">
          <div className="inline-flex items-center gap-3 rounded-lg border border-slate-800 bg-slate-950 px-4 py-3">
            <span className="h-2.5 w-2.5 animate-pulse rounded-full bg-teal-400" />
            <span className="text-sm font-medium text-slate-300">{title}</span>
          </div>

          <p className="mt-3 max-w-xl text-sm text-slate-500">{description}</p>
        </div>

        {variant === "dashboard" ? (
          <DashboardSkeleton />
        ) : (
          <ManagementSkeleton />
        )}
      </div>
    </main>
  );
}
