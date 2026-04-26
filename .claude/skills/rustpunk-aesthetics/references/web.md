# Web Components and Patterns

## Surface Treatment

### Card Anatomy

Every card/panel follows this structure:

```
┌─ border-top (accent color, 2-3px, stronger than other borders)
│
│  ┌─ status indicator (top-left or top-right)
│  │
│  │  TITLE (Chakra Petch 600)
│  │  // tagline (JetBrains Mono 11, accent color)
│  │
│  │  ── rust line (gradient divider) ──
│  │
│  │  Description body (JetBrains Mono 12, iron color)
│  │
│  └─ optional: deps, metadata, wave indicator
│
└─ optional: eroded corners, registration marks, rivets
```

### Eroded Corners

Clip card corners with triangular overlays to simulate material loss. Apply asymmetrically — never the same cut on all four corners. Typical: one large (36px top-right), one small (20px bottom-left), zero to two others.

```css
.corner-eroded-tr {
  position: absolute;
  top: 0; right: 0;
  width: 36px; height: 36px;
  background: linear-gradient(225deg, var(--char) 0%, var(--char) 45%, transparent 46%);
  opacity: 0.6;
}
```

### Registration Marks (Blueprint variant)

Small L-shaped corner marks indicating print alignment. 8×8px, 1.5px stroke in accent at 50% opacity.

### Rivet Marks (Salvage Tag variant)

8×8px circles at corners: 1.5px border in `border-medium`, `char-surface` fill.

### Rust Line (Divider)

Horizontal gradient simulating oxidation spread:

```css
.rust-line {
  height: 1px;
  background: linear-gradient(90deg,
    transparent 0%, #5C3A1E 8%, #B7410E 20%, #C75B2A 35%,
    #8B4513 50%, #B7410E 65%, #5C3A1E 85%, transparent 100%);
  opacity: 0.6;
}
```

---

## Backgrounds and Texture

### Noise Overlay

Canvas-generated grain, fixed position, full viewport:

- 256×256 resolution, tiled
- Per-pixel: random 0-25, RGB weighted warm (R×1.0, G×0.7, B×0.4), alpha 40
- Blend mode: `overlay`, opacity 0.6
- z-index above backgrounds, below text

### Scanlines

```css
.scanlines {
  background: repeating-linear-gradient(0deg,
    transparent, transparent 2px,
    rgba(0,0,0,0.06) 2px, rgba(0,0,0,0.06) 4px);
}
```

### Grid Paper (Blueprint variant)

SVG pattern: small grid 20×20px (0.3 strokeWidth), large grid 100×100px (0.8 strokeWidth), verdigris, overall opacity 0.08.

### Vignette (Phosphor variant)

```css
.vignette {
  background: radial-gradient(ellipse at center, transparent 50%, rgba(0,0,0,0.6) 100%);
}
```

---

## Motion

### Entry Animations

Stagger card entries: `animation-delay = index × 0.12s`.

```css
@keyframes cardIn {
  from { opacity: 0; transform: translateY(30px); }
  to { opacity: 1; transform: translateY(0); }
}
```

Hero elements: `fadeUp` with 0.2s stagger increments.

### Glitch Effect (Brand mark only)

Two offset clones of title text, each clipped to a horizontal band, with intermittent X-axis displacement. Clone 1: `oxide-red` at 30% opacity. Clone 2: `verdigris` at 20% opacity. Short bursts (50-80ms), long intervals (3-5s). Brand mark / hero title only, never body text.

### Flicker (Phosphor variant)

```css
@keyframes flicker {
  0%, 97%, 100% { opacity: 1; }
  98% { opacity: 0.7; }
  99% { opacity: 0.9; }
}
```

### Hover States

- Cards: border color shifts subtle → medium or accent, background lightens one step. Transition 0.3-0.4s ease.
- Text links: color shift to accent. No underline animation.
- **No transforms on hover.** No scale, no translateY. Rustpunk doesn't bounce — it holds steady.

---

## Layout Patterns

### Section Headers

```
[diamond] SECTION TITLE ──────────────── [optional count]
```

Diamond: 6×6px, rotated 45°, accent fill. Title: Chakra Petch 12px, 500 weight, 0.3em tracking, uppercase. Trailing line: 1px `border-subtle`, flex-grow.

### Margin Annotations

Vertical text along left viewport edge: `writing-mode: vertical-lr; transform: rotate(180deg)`. Chakra Petch 11px, `border-medium` color. Content: revision marks, file IDs, system status.

### Grid

2-column, 16px gap. Single column at 768px.

### Vertical Rhythm

- Section spacing: 48-80px
- Intra-section: 16-24px
- Card padding: 24-28px horizontal, 20-28px vertical
- Line height: body 1.7, terminal 1.5, headings 1.0-1.2

---

## Component Catalog

### Status Indicators

Chakra Petch 10px, 0.2em tracking, uppercase. 1px border in status color at 20% opacity. Padding 3px 8px.

| Status | Color |
|--------|-------|
| In progress | `hazard` #E8A524 |
| Planned | `verdigris` #43B3AE |
| Concept | `iron` #7A6F5D |
| Released | `oxide-red` #B7410E |

### Badges

Two-segment horizontal: `[label][value]`. Height 22px, JetBrains Mono 11px, border-radius 3px (outer corners only). Label bg: `#2A211A`. Value bg: `#3D2E1E` default or accent color.

### Code Blocks / Install Sections

Floating label positioned `top: -10px, left: 16px` with `char` background padding. Container: `char-surface` background, 1px `border-subtle`. Chakra Petch 12px for label, monospace for content.

### Dimension Lines (Blueprint variant)

End caps (1px × 8px), dashed center line, centered text label. Chakra Petch 11px, accent at 50% opacity.

---

## SVG Diagrams

When representing architecture or flow:

- Use SVG with `viewBox`, **never ASCII art** (breaks on mobile)
- Box fill: `char-surface` or near-transparent
- Box stroke: accent color at 50-60% opacity
- Text: IBM Plex Mono or sub-aesthetic body font, 11-13px
- Arrows: dashed (`strokeDasharray="6 3"`), accent at 60% opacity
- Arrowheads: open chevron path, not filled triangles
- Active elements: full accent color. Passive: `iron`/border tones.
- Set `minWidth` on the SVG container for horizontal scroll on narrow viewports

For documents, export SVG diagrams as high-resolution PNG (300 DPI minimum) and embed as images. Maintain the same color rules. Set image width to content width minus 0.5" for visual margin.

---

## CSS Variables Template

```css
:root {
  /* Accents */
  --oxide-red: #B7410E;
  --ember: #C75B2A;
  --hazard: #E8A524;
  --verdigris: #43B3AE;
  --phosphor: #D4A017;

  /* Text */
  --bone: #C4A882;
  --iron: #8A7E6E;
  --text-tertiary: #7A6852;
  --text-decorative: #6B5A42;
  --text-floor: #5C4A30;

  /* Surfaces */
  --char: #0D0A08;
  --char-surface: #0A0804;
  --char-raised: #14110C;

  /* Borders */
  --border-subtle: #1A1510;
  --border-medium: #2A211A;
  --border-strong: #3D2E1E;

  /* Fonts */
  --font-brand: 'Saira Stencil One', sans-serif;
  --font-heading: 'Chakra Petch', sans-serif;
  --font-body: 'JetBrains Mono', monospace;
  --font-terminal: 'VT323', monospace;
  --font-blueprint: 'Share Tech Mono', monospace;
  --font-outline: 'Dela Gothic One', sans-serif;
}
```
