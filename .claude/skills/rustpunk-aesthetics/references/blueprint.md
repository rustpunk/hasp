# Blueprint Sub-Aesthetic

> The full engineering-drawing visual vocabulary for the Blueprint sub-aesthetic.
> Supersedes brief notes on Registration Marks and Dimension Lines in `web.md`.

## Philosophy

The Blueprint sub-aesthetic is the technical drawing layer of the rustpunk system — salvaged
schematics from a world where CAD suites no longer exist and every diagram is drawn by hand on
drafting paper. The aesthetic reads: *this was measured precisely, then survived exposure*.

Verdigris replaces oxide-red as the accent throughout. The background deepens toward teal-black
rather than warm char. Grid paper replaces noise grain as the primary texture. Every visual
element should look like it belongs on a technical specification sheet: dimension lines, corner
registration marks, title block annotations, numbered callouts.

**Core rule**: oxide surfaces feel manufactured. Blueprint surfaces feel *measured*.

---

## Color Overrides

The shared background scale shifts toward teal-black. Use these in place of the standard char scale:

| Token | Hex | Role |
|-------|-----|------|
| `bp-bg` | `#060C0B` | Page/body background |
| `bp-surface` | `#080F0E` | Card/panel background (default) |
| `bp-raised` | `#0A1412` | Card/panel background (hover) |
| `bp-border` | `#1A2E2A` | Default borders |
| `bp-border-h` | `#43B3AE40` | Hovered borders (verdigris, 25% alpha) |
| `bp-text` | `#8BBAB5` | Primary text |
| `bp-text-dim` | `#5A8A83` | Secondary text |
| `bp-text-mute` | `#5A7D78` | Body/description text |
| `bp-text-ghost` | `#4A6F68` | Ghost labels, wave indicators, low-priority marks |
| `bp-accent` | `#43B3AE` | Full verdigris — active elements, hover titles, accent strokes |
| `bp-accent-60` | `#43B3AE99` | 60% verdigris — dimension line caps, corner marks |
| `bp-accent-30` | `#43B3AE4D` | 30% verdigris — grid strokes (large), annotation lines |
| `bp-accent-10` | `#43B3AE1A` | 10% verdigris — grid fill, faint dividers |

### Cross-Cutting Color Exception

The "no mixing accent families" rule applies to **primary accent** and **text hierarchy**. Permitted exceptions:

- `hazard` (#E8A524) as a **status indicator** for non-active states (planned, warning). Use at ≤80% opacity for status dots and labels. Never as the card's dominant accent.
- `oxide-red` (#B7410E) as an **approval/rejection stamp** (APPROVED/REJECTED mark). Stamps are diegetic objects from a different context dropped onto the schematic — a red stamp on a blue print is the point. Use with heavy opacity reduction (≤25%) and physical rotation (−8° to −15°) to read as found-artifact rather than designed element.

**Rule restatement**: the primary accent family must be consistent within a component. Cross-cutting semantic colors are permitted when they carry meaning that the blueprint accent cannot.

---

## Background Texture

The canonical blueprint background is an SVG grid paper pattern — not noise grain (which belongs to oxide/phosphor).

```jsx
function GridBackground() {
  return (
    <svg style={{
      position: "fixed", inset: 0,
      width: "100%", height: "100%",
      zIndex: 0, opacity: 0.08,
      pointerEvents: "none",
    }}>
      <defs>
        <pattern id="smallGrid" width="20" height="20" patternUnits="userSpaceOnUse">
          <path d="M 20 0 L 0 0 0 20" fill="none" stroke="#43B3AE" strokeWidth="0.3" />
        </pattern>
        <pattern id="grid" width="100" height="100" patternUnits="userSpaceOnUse">
          <rect width="100" height="100" fill="url(#smallGrid)" />
          <path d="M 100 0 L 0 0 0 100" fill="none" stroke="#43B3AE" strokeWidth="0.8" />
        </pattern>
      </defs>
      <rect width="100%" height="100%" fill="url(#grid)" />
    </svg>
  );
}
```

Grid specs: fine cell 20×20px at 0.3 stroke; major cell 100×100px at 0.8 stroke; both `#43B3AE`; container `opacity: 0.08`. Do not exceed 0.12. Do **not** layer noise overlay or scanlines on top — texture layering destroys the clean drafting-paper read.

---

## Typography

Blueprint body text uses **Share Tech Mono** instead of JetBrains Mono. Share Tech Mono reads as a typewriter or drafting label machine — imprecise but deliberate. JetBrains Mono is too refined for blueprint surfaces.

| Element | Font | Size | Weight | Tracking | Color |
|---------|------|------|--------|----------|-------|
| Card title / crate name | Share Tech Mono | 20px | 400 | normal | `bp-text` rest, `bp-accent` hover |
| Section header | Share Tech Mono | 11px | 400 | 0.3em, uppercase | `bp-text-dim` |
| Tagline / annotation | Chakra Petch | 12–15px | 400 | normal | `bp-text-dim` |
| Body / description | Share Tech Mono | 12–13px | 400 | normal | `bp-text-mute` |
| Dep tags / micro labels | Share Tech Mono | 9–10px | 400 | normal | `bp-text-dim` |
| Wave / ghost labels | Share Tech Mono | 9px | 400 | normal | `bp-text-ghost` |
| Title-block stamps | Chakra Petch | 12–13px | 400 | normal | `bp-accent` at 50% |
| Approval stamps | Chakra Petch | 16–20px | 400 | normal | `oxide-red` at 20% |
| Dimension line labels | Chakra Petch | 11px | 400 | normal | `bp-accent` at 50% |
| Margin annotations | Chakra Petch | 11px | 400 | 0.1em | `bp-text-ghost` |
| Code / pre blocks | Share Tech Mono | 13px | 400 | normal | `bp-text-dim` |

Hero / brand title: **Dela Gothic One** (the outline brand mark variant), not Saira Stencil One. Render with `color: transparent` + `WebkitTextStroke: "1.5px #43B3AE"`. Reads as a drafted outline letterform rather than a filled industrial stamp.

---

## Engineering Drawing Components

These components constitute the "engineering drawing" layer. They simulate technical drawing conventions applied to interactive UI. All are decorative-structural and must never obscure primary content.

### Corner Registration Marks

L-shaped corner brackets indicating print registration alignment.

```jsx
function CornerMarks({ color = "#43B3AE60", size = 8, weight = 1.5 }) {
  const corners = [
    ["top", "left"], ["top", "right"],
    ["bottom", "left"], ["bottom", "right"],
  ];
  return corners.map(([v, h], i) => (
    <div key={i} style={{
      position: "absolute",
      [v]: -1, [h]: -1,
      width: size, height: size,
      borderTop:    v === "top"    ? `${weight}px solid ${color}` : "none",
      borderBottom: v === "bottom" ? `${weight}px solid ${color}` : "none",
      borderLeft:   h === "left"   ? `${weight}px solid ${color}` : "none",
      borderRight:  h === "right"  ? `${weight}px solid ${color}` : "none",
      pointerEvents: "none",
    }} />
  ));
}
```

Default: 8×8px, 1.5px stroke, `#43B3AE60`. Increase to `#43B3AE80` on hover. Apply to every blueprint card. Not for oxide or phosphor surfaces.

### Dimension Lines

Engineering measurement lines with end caps, dashed center, and centered text label.

```jsx
function DimensionLine({ label, style = {} }) {
  const cap = { width: 1, height: 8, background: "#43B3AE", opacity: 0.4 };
  const tick = { width: 8, height: 1, background: "#43B3AE", opacity: 0.4 };
  return (
    <div style={{ display: "flex", alignItems: "center", ...style }}>
      <div style={tick} />
      <div style={{ ...cap, marginLeft: -1 }} />
      <div style={{
        flex: 1, height: 1,
        background: "#43B3AE", opacity: 0.2,
        borderTop: "1px dashed #43B3AE30",
      }} />
      <span style={{
        fontFamily: "'Chakra Petch', sans-serif",
        fontSize: 11, color: "#43B3AE", opacity: 0.5,
        padding: "0 6px", whiteSpace: "nowrap",
      }}>
        {label}
      </span>
      <div style={{
        flex: 1, height: 1,
        background: "#43B3AE", opacity: 0.2,
        borderTop: "1px dashed #43B3AE30",
      }} />
      <div style={cap} />
      <div style={{ ...tick, marginLeft: -1 }} />
    </div>
  );
}
```

Typical uses: scroll-down indicator at hero bottom; spacing annotation between sections. Opacity on container: 0.35–0.5. Never full opacity.

### Title Block Stamps

Floating label that interrupts a container's top border. Background fill must match the page background to simulate a cutout in the border line.

```jsx
<div style={{ position: "relative", border: "1px solid #1A2E2A", padding: "32px 28px", background: "#080F0E" }}>
  <div style={{
    position: "absolute", top: -10, left: 20,
    background: "#060C0B",    // must match PAGE background, not panel
    padding: "0 12px",
    fontFamily: "'Chakra Petch', sans-serif",
    fontSize: 13, color: "#43B3AE80",
  }}>
    design philosophy
  </div>
</div>
```

Rules: `top: -10px` positions at border crossing. Background color **must exactly match parent page background** (`bp-bg` / `#060C0B`). Font: Chakra Petch 12–13px, verdigris at 40–60% opacity. Content: lowercase, matter-of-fact ("design philosophy", "Cargo.toml", "rev.02").

### Numbered Callout Rows

Sequential numbered items in a technical note block.

```jsx
<div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 13, lineHeight: 2, color: "#5A7D78" }}>
  {items.map((item, i) => (
    <p key={i} style={{ margin: "0 0 12px" }}>
      <span style={{ color: "#43B3AE", opacity: 0.6 }}>
        {String(i + 1).padStart(2, "0")}.
      </span>{" "}
      {item}
    </p>
  ))}
</div>
```

Number format: zero-padded two digits (`01.`, `02.`). Color: `bp-accent` at 60% opacity. Body: Share Tech Mono, `bp-text-mute`. Line height: 2.0.

### Section Header Rows

Use a small geometric SVG mark (crosshair-square or target circle) rather than the oxide diamond. Dashed flex-grow divider.

```jsx
// Crosshair-square mark (primary sections)
<div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 40 }}>
  <svg width="12" height="12">
    <rect x="1" y="1" width="10" height="10" fill="none" stroke="#43B3AE" strokeWidth="1" opacity="0.5" />
    <line x1="3" y1="6" x2="9" y2="6" stroke="#43B3AE" strokeWidth="0.8" opacity="0.5" />
    <line x1="6" y1="3" x2="6" y2="9" stroke="#43B3AE" strokeWidth="0.8" opacity="0.5" />
  </svg>
  <h2 style={{
    fontFamily: "'Share Tech Mono', monospace",
    fontSize: 11, letterSpacing: "0.3em",
    color: "#5A8A83", textTransform: "uppercase",
    margin: 0,
  }}>
    Schematic
  </h2>
  <div style={{ flex: 1, borderTop: "1px dashed #1A2E2A" }} />
  <span style={{ fontFamily: "'Chakra Petch', sans-serif", fontSize: 12, color: "#4A6F68" }}>
    4 indexed
  </span>
</div>

// Target-circle mark (secondary sections)
<svg width="12" height="12">
  <circle cx="6" cy="6" r="4" fill="none" stroke="#43B3AE" strokeWidth="0.8" opacity="0.5" />
  <circle cx="6" cy="6" r="1.5" fill="#43B3AE" opacity="0.4" />
</svg>
```

Divider: `1px dashed #1A2E2A`. Never solid — dashed reads as provisional.

### Crosshair Center Mark

Large translucent crosshair at a page's geometric center. Hero sections only.

```jsx
<svg width="40" height="40" style={{
  position: "absolute",
  top: "50%", left: "50%",
  transform: "translate(-50%, -50%)",
  opacity: 0.1,
  pointerEvents: "none",
}}>
  <line x1="20" y1="0"  x2="20" y2="40" stroke="#43B3AE" strokeWidth="0.5" />
  <line x1="0"  y1="20" x2="40" y2="20" stroke="#43B3AE" strokeWidth="0.5" />
  <circle cx="20" cy="20" r="12" fill="none" stroke="#43B3AE" strokeWidth="0.5" />
</svg>
```

Opacity: 0.08–0.12. Never in interactive areas.

### Dep / Tag Pills

Dashed border, no background fill — reads as a labeled void.

```jsx
<span style={{
  fontFamily: "'Share Tech Mono', monospace",
  fontSize: 10, color: "#5A8A83",
  border: "1px dashed #2A3F3B",
  padding: "2px 6px",
}}>
  miette
</span>
```

No `borderRadius`. No background. Dashed border `#2A3F3B`. Text `bp-text-dim`. Cluster in flex row with 8px gap. Do not apply `bp-accent` to dep tags — they are inventory, not emphasis.

### Margin Annotation

Vertical identifier along the left viewport edge.

```jsx
<div style={{ position: "fixed", top: 40, left: 20, zIndex: 10, pointerEvents: "none" }}>
  <div style={{
    writingMode: "vertical-lr",
    transform: "rotate(180deg)",
    fontFamily: "'Chakra Petch', sans-serif",
    fontSize: 11, color: "#4A6F68",
    letterSpacing: "0.1em",
  }}>
    rustpunk.rs // workshop drawing rev.02
  </div>
</div>
```

Content pattern: `[project identifier] // [drawing type] [revision]`. Color: `bp-text-ghost`. Fixed position, pointer-events none.

---

## Motion

### Card Entry (`blueprintIn`)

```css
@keyframes blueprintIn {
  from { opacity: 0; transform: translateY(16px); }
  to   { opacity: 1; transform: translateY(0); }
}
```

Stagger: `animation-delay = index × 0.1s`. Duration: 0.5s ease. Subtler than oxide `cardIn` (16px vs 30px lift).

### Stroke Draw-In (`drawIn`)

Makes decorative SVG paths look hand-drafted. The most blueprint-specific animation.

```css
@keyframes drawIn {
  from { stroke-dashoffset: 300; }
  to   { stroke-dashoffset: 0; }
}
```

```jsx
<path
  d="M 10 30 Q 40 8, 80 20 Q 120 32, 150 12"
  fill="none" stroke="#43B3AE" strokeWidth="1" opacity="0.3"
  strokeDasharray="300"
  style={{ animation: "drawIn 1.5s ease 1s both" }}
/>
```

Rules:
- `strokeDasharray` must equal or exceed total path length. 300 is safe for short curves (< 200px). Measure long paths with `path.getTotalLength()`.
- Delay should exceed hero text fade-ins — drawn lines are ambient, not primary.
- Duration: 1.0–2.0s ease. Slower reads as more deliberate/hand-drawn.
- Opacity: 0.2–0.4. Never full opacity.
- One or two drawn paths per hero section max. Do not animate grid lines, corner marks, or dimension lines — those are structural, not gestural.

### Hero Element Stagger (`fadeUp`)

```css
@keyframes fadeUp {
  from { opacity: 0; transform: translateY(24px); }
  to   { opacity: 1; transform: translateY(0); }
}
```

Increasing delay per element: 0.2s → 0.4s → 0.5s → 0.6s → 0.7s → 0.9s → 1.2s. Scroll indicator / dimension line animates last.

---

## Blueprint Anti-Patterns

In addition to the global web anti-patterns:

- **No noise overlay or warm texture.** The grid is the texture. Grain reads as corrosion; blueprint surfaces are exposed but not oxidized.
- **No warm colors in structural elements.** `bone`, `iron`, `ember`, `oxide-red` in structural positions (borders, dividers, headings) break the cold-precision read. Exception: approval stamps and hazard status (per cross-cutting rule).
- **No solid dividers.** Blueprint dividers are dashed. Solid lines are for oxide surfaces.
- **No Saira Stencil One.** Blueprint brand mark is Dela Gothic One with transparent fill and verdigris stroke.
- **No `drawIn` on structural lines.** Only decorative annotation curves and hand-drawn arrows get stroke animation.
- **No filled dep/tag pills.** Blueprint tags are dashed-border voids.
- **No center-aligned body text.** Applies double in blueprint — engineering notes are always left-aligned.

---

## Quick Reference Card

```
Background:     #060C0B + GridBackground SVG (opacity 0.08)
Panels:         #080F0E background, 1px solid #1A2E2A border
Hover panels:   #0A1412 background, 1px solid #43B3AE40 border
Corner marks:   8×8px L-brackets, 1.5px #43B3AE60
Dividers:       1px dashed #1A2E2A
Title labels:   Chakra Petch 12px, #43B3AE80, background #060C0B (cuts border)
Body font:      Share Tech Mono (not JetBrains Mono)
Headings:       Share Tech Mono 11px, 0.3em tracking, uppercase, #5A8A83
Card titles:    Share Tech Mono 20px, #8BBAB5 rest / #43B3AE hover
Section marks:  12×12px SVG crosshair or target circle, #43B3AE at 50%
Annotations:    Chakra Petch 11-12px, #43B3AE at 40-60% opacity
Brand mark:     Dela Gothic One, transparent fill, WebkitTextStroke 1.5px #43B3AE
Entry anim:     blueprintIn, 0.5s, stagger 0.1s per card
Drawn paths:    drawIn, 1.5s ease, delay > hero text, opacity 0.2-0.4
Status dots:    6px circle, hazard/verdigris/iron per semantic state
Approval stamp: Chakra Petch 18px, oxide-red 20% opacity, rotate(-8deg), dashed border
```
