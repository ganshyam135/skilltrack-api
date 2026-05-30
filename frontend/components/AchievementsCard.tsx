type AchievementsCardProps = {
  achievements: string[];
};

export default function AchievementsCard({
  achievements,
}: AchievementsCardProps) {
  return (
    <div className="rounded-2xl border border-gray-800 bg-gray-950 p-6">
      <h2 className="text-2xl font-semibold mb-6">Achievements</h2>

      {achievements.length === 0 ? (
        <p className="text-gray-400">No achievements unlocked yet.</p>
      ) : (
        <div className="space-y-3">
          {achievements.map((achievement, index) => (
            <div
              key={index}
              className="rounded-xl border border-yellow-900 bg-yellow-950/20 p-4"
            >
              {achievement}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
