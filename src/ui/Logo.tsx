import { useEffect, useId, useState } from 'react';

/**
 * The Sharingan eye from the Phishing Email Analyzer, with its tomoe turning.
 *
 * Drawn once and shown four times: the whole eye, then three horizontal
 * slices of it shifted sideways, which is the glitch. The rotation lives
 * inside the shared drawing, so every slice turns in step with the eye.
 * While anything is being parsed it turns faster, so the logo doubles as a
 * sign that work is going on.
 */
export function Logo({ busy = false, size = 34 }: { busy?: boolean; size?: number }) {
  const id = useId().replace(/[^a-zA-Z0-9]/g, '');
  const eye = `${id}eye`;
  const tomoe = `${id}t`;

  // Motion is a flourish, so it stops for anyone who has asked their system
  // for less of it.
  const [still, setStill] = useState(
    () => typeof matchMedia === 'function' && matchMedia('(prefers-reduced-motion: reduce)').matches,
  );
  useEffect(() => {
    if (typeof matchMedia !== 'function') return;
    const q = matchMedia('(prefers-reduced-motion: reduce)');
    const on = () => setStill(q.matches);
    q.addEventListener('change', on);
    return () => q.removeEventListener('change', on);
  }, []);

  return (
    <svg
      className="logo"
      viewBox="-5 -5 110 110"
      width={size}
      height={size}
      role="img"
      aria-label="4ENSICS"
    >
      <defs>
        <g id={eye}>
          <circle cx="50" cy="50" r="48" className="logo-iris" />
          <circle cx="50" cy="50" r="46.5" className="logo-ring" strokeWidth="2.5" />
          <g>
            <g id={tomoe} className="logo-ink">
              <path d="M50 12A38 38 0 0 1 81 28Q69 22 50 26Z" />
              <circle cx="50" cy="19" r="7" />
            </g>
            <use href={`#${tomoe}`} transform="rotate(120 50 50)" />
            <use href={`#${tomoe}`} transform="rotate(240 50 50)" />
            {!still && (
              <animateTransform
                // A new key restarts the animation at the new speed; changing
                // dur on a running animation is not picked up everywhere.
                key={busy ? 'fast' : 'slow'}
                attributeName="transform"
                type="rotate"
                from="0 50 50"
                to="360 50 50"
                dur={busy ? '0.8s' : '6s'}
                repeatCount="indefinite"
              />
            )}
          </g>
          <circle cx="50" cy="50" r="8" className="logo-ink" />
        </g>
        <clipPath id={`${id}s1`}>
          <rect x="-10" y="22" width="120" height="7" />
        </clipPath>
        <clipPath id={`${id}s2`}>
          <rect x="-10" y="47" width="120" height="5" />
        </clipPath>
        <clipPath id={`${id}s3`}>
          <rect x="-10" y="70" width="120" height="6" />
        </clipPath>
      </defs>
      <use href={`#${eye}`} />
      <g clipPath={`url(#${id}s1)`}>
        <use href={`#${eye}`} x="7" />
      </g>
      <g clipPath={`url(#${id}s2)`}>
        <use href={`#${eye}`} x="-6" />
      </g>
      <g clipPath={`url(#${id}s3)`}>
        <use href={`#${eye}`} x="5" />
      </g>
    </svg>
  );
}
