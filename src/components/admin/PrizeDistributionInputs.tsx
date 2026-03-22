import React, { useState, useEffect } from 'react';

interface PrizeDistributionInputsProps {
  prizePool: number;
  initialDistribution?: any[];
}

export default function PrizeDistributionInputs({ prizePool, initialDistribution = [] }: PrizeDistributionInputsProps) {
  const [distribution, setDistribution] = useState<number[]>(Array(10).fill(0));

  useEffect(() => {
    if (initialDistribution && initialDistribution.length > 0) {
      const newDist = Array(10).fill(0);
      initialDistribution.forEach((item, index) => {
        if (index < 10) {
          newDist[index] = item.points || 0;
        }
      });
      setDistribution(newDist);
    }
  }, [initialDistribution]);

  const handleChange = (index: number, value: number) => {
    const newDist = [...distribution];
    newDist[index] = value;
    setDistribution(newDist);
  };

  return (
    <div className="md:col-span-2 space-y-3">
      <label className="block text-gray-500 text-[9px] font-black uppercase tracking-widest mb-1">Prize Distribution (Top 1 to Top 10)</label>
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
        {distribution.map((points, index) => {
          const percent = prizePool > 0 && points > 0 ? ((points / prizePool) * 100).toFixed(1) : 0;
          return (
            <div key={index} className="bg-[#131B2F] p-2 rounded-lg border border-gray-800 relative">
              <label className="block text-gray-400 text-[10px] font-bold mb-1">Top {index + 1}</label>
              <input
                type="number"
                name={`top${index + 1}Prize`}
                value={points || ''}
                onChange={(e) => handleChange(index, Number(e.target.value))}
                className="w-full bg-[#0B1121] border border-gray-800 rounded py-1 px-2 text-white focus:outline-none focus:border-yellow-500 transition-colors font-bold text-xs"
                placeholder="0"
              />
              {points > 0 && (
                <div className="absolute top-2 right-2 text-[9px] text-yellow-500 font-bold">
                  {percent}%
                </div>
              )}
            </div>
          );
        })}
      </div>
      <p className="text-[10px] text-gray-500">Leave empty or 0 to skip. Percentage is calculated automatically.</p>
    </div>
  );
}
