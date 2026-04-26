# Typography

## Font Stack

| Font | Weight(s) | Role | Document Role |
|------|-----------|------|---------------|
| **Saira Stencil One** | 400 | Brand mark, hero titles only | Cover page title only |
| **Dela Gothic One** | 400 | Blueprint outline brand mark | Not used in documents |
| **Chakra Petch** | 300, 400, 500, 600 | Section headers, UI labels, annotations, callouts | Document headings (H1–H4), callout labels, table headers |
| **JetBrains Mono** | 300, 400, 500 | Body text, code, descriptions, taglines | Code blocks, inline code, CLI examples |
| **Share Tech Mono** | 400 | Blueprint body text, technical readouts | Not used in documents |
| **VT323** | 400 | Terminal / CRT / phosphor variant only | Not used in documents |
| **IBM Plex Mono** | 300, 400, 500 | Code blocks, JSON output, diagrams | Alternative code block font |

## Font Fallback Chains (Document Portability)

PDF is the canonical delivery format — export to PDF with fonts embedded for pixel-perfect rendering. When distributing editable .docx files, these fallback chains ensure graceful degradation.

| Primary Font | Fallback 1 | Fallback 2 | System Fallback |
|-------------|-----------|-----------|----------------|
| Chakra Petch | Barlow Condensed | Calibri | Arial |
| JetBrains Mono | Cascadia Code | Consolas | Courier New |
| Saira Stencil One | Impact | Arial Black | Arial |
| IBM Plex Mono | Source Code Pro | Consolas | Courier New |

**Fallback philosophy**: Calibri and Consolas are acceptable fallbacks — they are not aesthetic choices, they are survival strategies. The document should still communicate "technical, structured, industrial" even in fallback. Arial and Courier New are the floor.

**Font embedding**: All primary fonts are SIL Open Font Licensed (OFL) and may be freely embedded. The `docx-js` library does not support font embedding directly. For guaranteed rendering, always provide a PDF alongside the .docx.

**Saira Stencil One caveat**: This font ships as a single weight (Regular 400 only). Applying bold in Word triggers synthetic faux-bold, which crudely thickens strokes. Never apply bold to Saira Stencil One.

## Rules

- **Never use cursive or script fonts.** No Caveat, no handwriting faces. Annotations use Chakra Petch Light (300).
- **Never use Inter, Roboto, or system fonts for web.** These break the aesthetic immediately.
- **Documents may use Calibri or Consolas as fallbacks** when custom fonts are unavailable. Only context where system fonts are acceptable.
- Saira Stencil One is reserved for the `RUSTPUNK` brand mark, hero text, and document cover page titles. Not for body copy or section headers.
- VT323 is only for the phosphor sub-aesthetic in web contexts. Do not use in documents.
- All monospace body text defaults to JetBrains Mono. Share Tech Mono is the web blueprint variant.

## Scale (Web)

| Element | Font | Size | Weight | Tracking |
|---------|------|------|--------|----------|
| Hero title | Saira Stencil One | clamp(48px, 9vw, 96px) | 400 | 0.06em |
| Section header | Chakra Petch | 12-13px | 500 | 0.15-0.3em, uppercase |
| Card title | Chakra Petch | 20-22px | 600 | 0.04em |
| Tagline / code comment | JetBrains Mono | 11px | 400 | 0.03em |
| Body text | JetBrains Mono | 12-13px | 400 | normal |
| Terminal text | VT323 | 14-20px | 400 | 0.04em |
| Annotation / callout | Chakra Petch | 12-15px | 300 | normal |
| Micro label | Chakra Petch or JetBrains Mono | 9-10px | 400 | 0.15-0.2em, uppercase |

## Scale (Documents)

Document typography uses point sizes. docx-js `size` values are in half-points: size 24 = 12pt.

| Element | Font | Size (pt) | Weight | Tracking | Notes |
|---------|------|-----------|--------|----------|-------|
| Cover title | Saira Stencil One | 36–48pt | 400 | expanded 3pt | Cover page only |
| Cover subtitle | Chakra Petch | 14–16pt | 300 | expanded 1pt | Below cover title |
| H1 — Document title | Chakra Petch | 22pt | 600 | expanded 2pt | ALL CAPS. 3pt bottom border in `oxide-red`. |
| H2 — Section header | Chakra Petch | 16pt | 600 | normal | Title Case. 18pt space before, 8pt after. |
| H3 — Subsection | Chakra Petch | 13pt | 500 | expanded 1pt, uppercase | 14pt space before, 6pt after. |
| H4 — Minor heading | Chakra Petch | 11pt | 500 | normal | Title Case. |
| Body text | Calibri | 11pt | 400 | normal | 1.15 line spacing. 6pt space after paragraph. |
| Code block | JetBrains Mono | 9.5pt | 400 | normal | Single line spacing. In shaded container. |
| Inline code | JetBrains Mono | 9.5pt | 400 | normal | `doc-surface` background shading on the run. |
| Table header | Chakra Petch | 10pt | 600 | expanded 1pt, uppercase | White text on `oxide-red` background. |
| Table body | Calibri | 10pt | 400 | normal | Alternating row tint: white / `doc-surface`. |
| Callout label | Chakra Petch | 10pt | 600 | expanded 1pt, uppercase | "NOTE", "WARNING", "TIP" prefix. |
| Callout body | Calibri | 10.5pt | 400 | normal | In shaded container with accent left border. |
| Footer / metadata | Chakra Petch | 8pt | 400 | expanded 0.5pt | Page numbers, revision marks, doc ID. |
| Maker's mark | JetBrains Mono | 8pt | 300 | normal | "— Feed the kiln. —" or tagline. Last page. |

**Why Calibri for body text**: JetBrains Mono is the web body font, but monospace body text in documents is fatiguing for extended reading (30+ pages). Calibri provides superior readability for dense technical prose while JetBrains Mono is reserved for code and data where monospace is functionally necessary.

## Google Fonts Import (Web)

```
https://fonts.googleapis.com/css2?family=Chakra+Petch:wght@300;400;500;600&family=JetBrains+Mono:wght@300;400;500&family=Saira+Stencil+One&family=Share+Tech+Mono&family=VT323&family=Dela+Gothic+One&family=IBM+Plex+Mono:wght@300;400;500&display=swap
```
