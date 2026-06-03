type Session = {
  id: number;
  duration: number;
  notes: string | null;
  created_at: string;
};

type RecentActivityProps = {
  sessions: Session[];
};

export default function RecentActivity({ sessions }: RecentActivityProps) {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-950 p-6 shadow-sm">
      <h2 className="text-lg font-semibold text-white">Recent Activity</h2>
      <p className="mb-6 mt-1 text-sm text-slate-400">Latest study sessions</p>

      {sessions.length === 0 ? (
        <p className="text-sm text-slate-400">No study sessions yet.</p>
      ) : (
        <div className="space-y-4">
          {sessions.map((session) => (
            <div
              key={session.id}
              className="rounded-lg border border-slate-800 bg-slate-900/50 p-4"
            >
              <div className="flex items-center justify-between gap-4">
                <span className="font-medium text-white">{session.duration} mins</span>

                <span className="shrink-0 text-sm text-slate-400">
                  {new Date(session.created_at).toLocaleDateString()}
                </span>
              </div>

              <p className="mt-2 text-sm text-slate-400">
                {session.notes || "No notes"}
              </p>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
