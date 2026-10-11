import React from 'react';

export default function Header({ title, subtitle }) {
  return (
    <header className="px-8 py-5 border-b border-[#E5E9EF] bg-[#FFFFFF] flex items-center justify-between sticky top-0 z-10">
      <div>
        <h1 className="text-lg font-semibold text-[#202631] tracking-tight">{title}</h1>
        {subtitle && <p className="text-xs text-[#687385] mt-0.5">{subtitle}</p>}
      </div>
      <div className="flex items-center gap-3">
        <span className="text-[11px] font-medium text-[#687385] bg-[#F3F5F7] px-2.5 py-1 rounded-md border border-[#E5E9EF]">
          VORTEXA 3.0
        </span>
        <span className="text-[11px] font-medium text-[#4263A6] bg-[#E8EEF8] px-2.5 py-1 rounded-md border border-[#4263A622]">
          Policy Active: v2.1
        </span>
      </div>
    </header>
  );
}
