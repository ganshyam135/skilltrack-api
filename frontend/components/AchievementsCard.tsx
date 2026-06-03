type AchievementsCardProps = {
  achievements: string[];
};

export default function AchievementsCard({ achievements }: AchievementsCardProps) {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-950 p-6 shadow-sm">
      <h2 className="text-lg font-semibold text-white">Achievements</h2>
      <p className="mb-6 mt-1 text-sm text-slate-400">
        Milestones unlocked from your study history
      </p>

      {achievements.length === 0 ? (
        <p className="text-sm text-slate-400">No achievements unlocked yet.</p>
      ) : (
        <div className="space-y-3">
          {achievements.map((achievement, index) => (
            <div
              key={index}
              className="rounded-lg border border-amber-900 bg-amber-950/30 p-4 text-sm text-amber-100"
            >
              {achievement}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
