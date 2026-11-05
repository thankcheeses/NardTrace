/**
 * NardTrace icon set.
 *
 * One file, no dependency. Every glyph is a 24x24 stroked path drawn to the
 * same spec the sidebar already used: fill none, stroke currentColor,
 * stroke-width 1.8, round caps and joins. Colour comes from the Tailwind
 * text-* class on the call site, so an icon inherits whatever evidence colour
 * its row already carries (text-confirmed, text-assume, ...).
 *
 * Deliberately plain line work. This is an evidence tool: an icon here is a
 * label, not decoration, and anything more illustrative would compete with
 * the findings for the reader's attention.
 */

/** name -> path data. A value may be a single `d` or an array of subpaths. */
export const ICON_PATHS = {
  // --- navigation (the sidebar's original seven, kept here as the one source)
  desk: 'M3 11l9-8 9 8M5 10v10h14V10',
  email: 'M3 6h18v12H3zM3 6l9 7 9-7',
  ip: 'M12 3a9 9 0 100 18 9 9 0 000-18zM3 12h18M12 3c3 3 3 15 0 18M12 3c-3 3-3 15 0 18',
  domain: 'M4 7h16M4 12h16M4 17h10',
  url: 'M10 14a4 4 0 005.7 0l3-3a4 4 0 00-5.7-5.7l-1 1M14 10a4 4 0 00-5.7 0l-3 3a4 4 0 005.7 5.7l1-1',
  file: 'M6 3h8l4 4v14H6zM14 3v4h4M9 13h6M9 17h6',
  cases: 'M4 6h6l2 2h8v11H4z',

  // --- the four evidence tags, one glyph each
  // CONFIRMED: closed circle, struck through. Directly observed.
  confirmed: ['M21 12a9 9 0 11-18 0 9 9 0 0118 0', 'M8.4 12.3l2.6 2.6 4.6-5.3'],
  // EXTERNAL INTEL: arrow landing in a tray. Came from somewhere else.
  intel: ['M12 3v9', 'M8.8 8.8L12 12l3.2-3.2', 'M4 15v3a2 2 0 002 2h12a2 2 0 002-2v-3'],
  // ASSUMPTION: approximation waves. Inferred, not observed.
  assume: ['M21 12a9 9 0 11-18 0 9 9 0 0118 0', 'M8 11c1-1 2-1 3 0s2 1 3 0', 'M8 14.6c1-1 2-1 3 0s2 1 3 0'],
  // UNKNOWN: circle with a single flat dash. Nothing to report.
  unknown: ['M21 12a9 9 0 11-18 0 9 9 0 0118 0', 'M8.5 12h7'],

  // --- actions
  copy: 'M9 9V5h10v10h-4M5 9h10v10H5z',
  check: 'M5 12.8l4.2 4.2L19 7.4',
  download: 'M12 4v10M8.5 10.5L12 14l3.5-3.5M5 18h14',
  export: 'M12 16V4M8.5 7.5L12 4l3.5 3.5M5 14v4a2 2 0 002 2h10a2 2 0 002-2v-4',
  upload: 'M12 18V8M8.5 11.5L12 8l3.5 3.5M5 5h14',
  verify: ['M12 3l7.5 3v6c0 4.2-3.1 7.6-7.5 9-4.4-1.4-7.5-4.8-7.5-9V6z', 'M9 12.2l2.2 2.2 4.2-4.4'],
  redact: ['M3 3l18 18', 'M10.6 10.7a2 2 0 002.8 2.8', 'M6.1 6.4C4.3 7.7 2.9 9.6 2 12c1.9 4 5.4 6.4 10 6.4 1.7 0 3.3-.4 4.7-1.1', 'M9.9 5.8A11 11 0 0112 5.6c4.6 0 8.1 2.4 10 6.4a13 13 0 01-2.3 3.4'],
  report: 'M6 21V4h12l-2.5 4.5L18 13H6',
  attach: 'M15.7 8.3l-6.4 6.4a2.3 2.3 0 103.2 3.2l6.4-6.4a4.2 4.2 0 10-5.9-5.9L6.4 12.2a6 6 0 108.5 8.5l1-1',
  linkOut: 'M14 5h5v5M19 5l-7.4 7.4M18 14v4a2 2 0 01-2 2H6a2 2 0 01-2-2V8a2 2 0 012-2h4',
  refresh: 'M20 12a8 8 0 11-2.6-5.9M20 4v4h-4',
  trash: 'M4 7h16M9 7V5h6v2M6 7l1 13h10l1-13M10 11v5M14 11v5',
  search: ['M15.5 15.5L20 20', 'M17 10.5a6.5 6.5 0 11-13 0 6.5 6.5 0 0113 0'],
  plus: 'M12 5v14M5 12h14',
  clock: ['M21 12a9 9 0 11-18 0 9 9 0 0118 0', 'M12 7.6V12l3 2'],

  // --- disclosure (replaces the literal triangle characters)
  chevronDown: 'M6 9.5l6 6 6-6',
  chevronRight: 'M9.5 6l6 6-6 6',
}

/** Icon names, for anyone iterating (a style page, a test). */
export const ICON_NAMES = Object.keys(ICON_PATHS)

/**
 * <Icon name="confirmed" className="h-4 w-4 text-confirmed" />
 *
 * Decorative by default (aria-hidden). Pass `title` when the icon is the only
 * thing carrying the meaning — then it is exposed as an image with that label.
 */
export function Icon({ name, className = 'h-4 w-4', title, strokeWidth = 1.8, ...rest }) {
  const d = ICON_PATHS[name]
  if (!d) return null
  const subpaths = Array.isArray(d) ? d : [d]
  return (
    <svg
      viewBox="0 0 24 24"
      className={className}
      fill="none"
      stroke="currentColor"
      strokeWidth={strokeWidth}
      strokeLinecap="round"
      strokeLinejoin="round"
      role={title ? 'img' : undefined}
      aria-hidden={title ? undefined : 'true'}
      aria-label={title}
      focusable="false"
      {...rest}
    >
      {title && <title>{title}</title>}
      {subpaths.map((p, i) => <path key={i} d={p} />)}
    </svg>
  )
}

/** Evidence tag -> icon name, so a badge and its glyph cannot drift apart. */
export const STATUS_ICON = {
  'CONFIRMED': 'confirmed',
  'EXTERNAL INTEL': 'intel',
  'ASSUMPTION': 'assume',
  'UNKNOWN': 'unknown',
}

export default Icon
