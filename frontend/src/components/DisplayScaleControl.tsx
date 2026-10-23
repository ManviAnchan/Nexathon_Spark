import React from 'react';
import { createPortal } from 'react-dom';
import { Minus, Plus, ZoomIn } from 'lucide-react';

interface DisplayScaleControlProps {
  value: number;
  theme: 'light' | 'dark';
  onChange: (value: number) => void;
}

export const DisplayScaleControl: React.FC<DisplayScaleControlProps> = ({ value, theme, onChange }) => createPortal(
  <div className="display-scale-control" data-theme={theme} role="group" aria-label="Display size">
    <button
      type="button"
      aria-label="Reset display size to 100%"
      title="Reset display size to 100%"
      onClick={() => onChange(100)}
    >
      <ZoomIn className="display-scale-icon" aria-hidden="true" />
    </button>
    <button
      type="button"
      aria-label="Decrease display size"
      title="Decrease display size"
      disabled={value <= 25}
      onClick={() => onChange(Math.max(25, value - 5))}
    >
      <Minus aria-hidden="true" />
    </button>
    <input
      aria-label="Display size"
      type="range"
      min="25"
      max="250"
      step="5"
      value={value}
      onChange={(event) => onChange(Number(event.target.value))}
    />
    <output aria-live="polite">{value}%</output>
    <button
      type="button"
      aria-label="Increase display size"
      title="Increase display size"
      disabled={value >= 250}
      onClick={() => onChange(Math.min(250, value + 5))}
    >
      <Plus aria-hidden="true" />
    </button>
  </div>,
  document.body,
);
