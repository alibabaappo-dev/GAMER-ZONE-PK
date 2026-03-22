import { useState, useEffect } from 'react';
import { db } from '../../lib/firebase';
import { doc, getDoc, setDoc } from 'firebase/firestore';
import { Save, Loader2 } from 'lucide-react';

export default function TaskRewardsSettings() {
  const [rewards, setRewards] = useState({
    join_2: 10,
    join_6: 20,
    win_3_matches: 10,
    weekly_join_20: 50
  });
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    const fetchRewards = async () => {
      const docRef = doc(db, 'settings', 'task_rewards');
      const docSnap = await getDoc(docRef);
      if (docSnap.exists()) {
        setRewards(docSnap.data() as any);
      }
      setLoading(false);
    };
    fetchRewards();
  }, []);

  const handleSave = async () => {
    setSaving(true);
    try {
      await setDoc(doc(db, 'settings', 'task_rewards'), rewards);
      alert('Rewards updated!');
    } catch (error) {
      console.error('Error updating rewards:', error);
      alert('Failed to update rewards.');
    }
    setSaving(false);
  };

  if (loading) return <div className="text-white">Loading...</div>;

  return (
    <div className="bg-[#1C1C1E] p-6 rounded-2xl border border-gray-800">
      <h2 className="text-xl font-black text-white mb-6 uppercase tracking-tight">Task Rewards Configuration</h2>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {Object.entries(rewards).map(([id, reward]) => (
          <div key={id} className="space-y-2">
            <label className="text-sm font-bold text-gray-400 uppercase">{id.replace('_', ' ')} Reward</label>
            <input
              type="number"
              value={reward}
              onChange={(e) => setRewards({ ...rewards, [id]: parseInt(e.target.value) })}
              className="w-full bg-black border border-gray-700 rounded-lg p-3 text-white font-bold"
            />
          </div>
        ))}
      </div>
      <button
        onClick={handleSave}
        disabled={saving}
        className="mt-8 w-full bg-yellow-500 hover:bg-yellow-600 text-black font-black py-3 rounded-xl transition-all flex items-center justify-center gap-2"
      >
        {saving ? <Loader2 className="animate-spin" size={20} /> : <Save size={20} />}
        Save Rewards
      </button>
    </div>
  );
}
