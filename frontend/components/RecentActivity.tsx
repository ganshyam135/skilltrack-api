type Session = {
  id: number;
  duration: number;
  notes: string;
  created_at: string;
};

type RecentActivityProps = {
  sessions: Session[];
};

export default function RecentActivity({ sessions }: RecentActivityProps) {
  return (
    <div className="rounded-2xl border border-gray-800 bg-gray-950 p-6">
      <h2 className="text-2xl font-semibold mb-6">Recent Activity</h2>

      {sessions.length === 0 ? (
        <p className="text-gray-400">No study sessions yet.</p>
      ) : (
        <div className="space-y-4">
          {sessions.map((session) => (
            <div
              key={session.id}
              className="rounded-xl border border-gray-800 p-4"
            >
              <div className="flex justify-between">
                <span className="font-medium">{session.duration} mins</span>

                <span className="text-sm text-gray-400">
                  {new Date(session.created_at).toLocaleDateString()}
                </span>
              </div>

              <p className="mt-2 text-gray-400">
                {session.notes || "No notes"}
              </p>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
