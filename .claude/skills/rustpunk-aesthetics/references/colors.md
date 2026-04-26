# Color System

## Primary Palette (Web)

| Token | Hex | Role |
|-------|-----|------|
| `oxide-red` | `#B7410E` | Primary accent, links, emphasis, the brand color |
| `ember` | `#C75B2A` | Hover/active states, interactive highlights |
| `hazard` | `#E8A524` | Warnings, status indicators, attention |
| `bone` | `#C4A882` | Primary text, headings |
| `verdigris` | `#43B3AE` | Blueprint sub-aesthetic accent |
| `phosphor` | `#D4A017` | Terminal sub-aesthetic text |
| `iron` | `#8A7E6E` | Secondary text, descriptions |
| `char` | `#0D0A08` | Primary background |

## Extended Scale (Backgrounds and Borders)

| Token | Hex | Role |
|-------|-----|------|
| `char-surface` | `#0A0804` | Card/panel background |
| `char-raised` | `#14110C` | Elevated surface |
| `border-subtle` | `#1A1510` | Default borders |
| `border-medium` | `#2A211A` | Hovered borders |
| `border-strong` | `#3D2E1E` | Active/focus borders |

## Document Palette (Light Background Variants)

On light/white document backgrounds, the web palette's dark-surface colors are irrelevant and several accent colors fail accessibility thresholds. These document-specific tokens solve both problems.

| Token | Hex | Role | WCAG on White |
|-------|-----|------|---------------|
| `doc-bg` | `#FFFFFF` | Primary document background | — |
| `doc-bg-warm` | `#FAF7F2` | Alternate warm page tint (cream) | — |
| `doc-surface` | `#F5F0E8` | Callout/code block backgrounds | — |
| `doc-surface-dark` | `#1C1610` | Cover page, header bands, inverted callouts | — |
| `doc-border` | `#D4C9B8` | Table borders, dividers on light backgrounds | — |
| `doc-border-strong` | `#B7410E` | Accent borders (left-edge callouts, table headers) | — |
| `doc-text` | `#1C1610` | Primary body text on light backgrounds | 17.4:1 |
| `doc-text-secondary` | `#5C5043` | Descriptions, metadata, secondary content | 7.2:1 |
| `doc-text-tertiary` | `#8A7E6E` | Annotations, revision marks, decorative labels | 4.0:1 |
| `oxide-red` | `#B7410E` | Heading text, table header backgrounds, accent borders | 5.5:1 ✓ AA |
| `hazard-dark` | `#9A6B00` | Warning text on white (darkened from `#E8A524`) | 5.1:1 ✓ AA |
| `verdigris-dark` | `#2D7A76` | Blueprint accent text on white (darkened from `#43B3AE`) | 5.0:1 ✓ AA |
| `hazard` | `#E8A524` | Background fills only (text on top: use `doc-text`) | 2.1:1 ✗ text |
| `verdigris` | `#43B3AE` | Background fills only (text on top: use `doc-text`) | 2.8:1 ✗ text |

**Critical rule**: `hazard` (#E8A524) and `verdigris` (#43B3AE) must never be used as text color on white backgrounds. They fail WCAG AA. Use the darkened variants (`hazard-dark`, `verdigris-dark`) for text, and the originals only as background fills or decorative borders.

## Contrast Rules

**On `char` background (web):**

- Primary text (`bone` #C4A882 on `char` #0D0A08): ~9.5:1
- Secondary text (`iron` #8A7E6E on `char` #0D0A08): ~5.2:1
- Tertiary text: never go below `#7A6852` (~4:1) on `char` backgrounds
- Decorative-only text (border labels, revision marks): minimum `#6B5A42` (~3:1)
- Interactive text (links, buttons): always use `oxide-red` or brighter

**On `doc-bg` background (documents):**

- Primary text (`doc-text` #1C1610 on white): 17.4:1
- Secondary text (`doc-text-secondary` #5C5043 on white): 7.2:1
- Tertiary/decorative text: never go above `#8A7E6E` (~4.0:1) on white
- Accent text (headings, links): `oxide-red` #B7410E at 5.5:1 — passes AA at all sizes
- Warning/status text: use darkened variants only (`hazard-dark`, `verdigris-dark`)

**Hard floor**: no text below 4.5:1 contrast in any context. If it can't be read on a phone in daylight, it fails.

## Sub-Aesthetic Color Mapping

Three sub-aesthetics share the background scale but swap the accent family:

| Sub-Aesthetic | Accent | Text Primary | Text Secondary | Use Case |
|---------------|--------|-------------|----------------|----------|
| **Oxide** (default) | `#B7410E` / `#C75B2A` | `#C4A882` | `#8A7E6E` | Landing pages, brand, cards |
| **Blueprint** | `#43B3AE` | `#8BBAB5` | `#5A8A83` | Technical docs, schematics, diagrams |
| **Phosphor** | `#D4A017` | `#D4A017` | `#8B7D3C` | Terminal UIs, CRT, CLI output |

Never mix accent families in the same component. A card is oxide OR blueprint OR phosphor — not a blend.

**Document sub-aesthetics**: Documents default to the Oxide sub-aesthetic. Blueprint is appropriate for technical reference appendices and schematic diagrams embedded as images. Phosphor is not used in documents — terminal output in docs uses the code block component with standard monospace styling.
