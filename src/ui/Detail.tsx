import type { Column, Row } from '../core/types';
import { fmt } from './format';
import { pretty } from './pretty';
import type { DetailPosition } from './storage';

/**
 * Every field of the selected row. Structured values - the event XML, the
 * payload, anything that is JSON - are laid out one element per line, because
 * a single line of XML is faithful and unreadable.
 */
export function Detail({
  columns,
  row,
  position,
  size,
  onClose,
}: {
  columns: Column[];
  row: Row;
  position: DetailPosition;
  /** Height underneath, width beside, in pixels. */
  size: number;
  onClose: () => void;
}) {
  return (
    <section
      className={`detail ${position}`}
      style={position === 'bottom' ? { height: size } : { width: size }}
      aria-label="Selected row"
    >
      <div className="detail-head">
        <span>Selected row</span>
        <button type="button" className="detail-close" onClick={onClose} aria-label="Close">
          ×
        </button>
      </div>
      <table>
        <tbody>
          {columns.map((c) => {
            const structured = pretty(row[c.key]);
            // A structured value gets the whole width, under its label, with
            // every element starting a line of its own; a line too long for
            // the panel wraps within itself.
            return structured !== null ? (
              <tr key={c.key} className="structured-row">
                <td colSpan={2}>
                  <div className="structured-label">{c.label}</div>
                  <pre className="structured">{structured}</pre>
                </td>
              </tr>
            ) : (
              <tr key={c.key}>
                <th>{c.label}</th>
                <td>{fmt(row[c.key])}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </section>
  );
}
