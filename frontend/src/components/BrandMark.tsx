import React from 'react';

export const BrandMark: React.FC<{ size?: number }> = ({ size = 18 }) => (
  <svg className="keynova-symbol" width={size} height={size} viewBox="0 0 32 32" fill="none" aria-hidden="true">
    <circle cx="16" cy="16" r="3.1" fill="currentColor" />
    <ellipse cx="16" cy="16" rx="12" ry="5.1" stroke="currentColor" strokeWidth="1.45" transform="rotate(-38 16 16)" />
    <ellipse cx="16" cy="16" rx="12" ry="5.1" stroke="currentColor" strokeWidth="1.45" transform="rotate(38 16 16)" />
    <circle cx="7.7" cy="9.1" r="1.7" fill="#a69778" />
    <circle cx="24.3" cy="9.1" r="1.7" fill="#89917e" />
    <circle cx="16" cy="28" r="1.35" fill="currentColor" opacity=".72" />
  </svg>
);
