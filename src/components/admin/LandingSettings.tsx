import { useState, useEffect } from 'react';
import { db } from '../../lib/firebase';
import { doc, onSnapshot, updateDoc } from 'firebase/firestore';

export default function LandingSettings() {
  const [settings, setSettings] = useState({
    activePlayers: '',
    tournaments: '',
    prizesDistributed: '',
    winners: ''
  });

  useEffect(() => {
    const unsub = onSnapshot(doc(db, 'settings', 'landing'), (docSnap) => {
      if (docSnap.exists()) {
        setSettings(docSnap.data() as any);
      }
    });
    return () => unsub();
  }, []);

  const handleSave = async () => {
    await updateDoc(doc(db, 'settings', 'landing'), settings);
    alert('Landing page settings updated!');
  };

  return (
    <div className="p-8 bg-[#0D0D0D] rounded-3xl border border-gray-800 shadow-2xl">
      <h2 className="text-3xl font-black text-white uppercase tracking-tight mb-8">Landing Page Settings</h2>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {Object.keys(settings).map((key) => (
          <div key={key}>
            <label className="block text-gray-400 text-sm font-bold uppercase tracking-widest mb-2">{key.replace(/([A-Z])/g, ' $1')}</label>
            <input 
              className="bg-[#1A1A1A] p-4 rounded-xl text-white border border-gray-700 w-full"
              value={settings[key as keyof typeof settings]}
              onChange={e => setSettings({...settings, [key]: e.target.value})}
            />
          </div>
        ))}
      </div>
      <button onClick={handleSave} className="mt-8 bg-yellow-500 hover:bg-yellow-400 text-black font-black uppercase tracking-widest p-4 rounded-xl w-full transition-all">
        Save Settings
      </button>
    </div>
  );
}
