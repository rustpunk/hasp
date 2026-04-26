# Document Design

## Strategy: Hybrid Dark/Light

Documents use a **hybrid approach**: dark cover page with light interior pages. This delivers the rustpunk atmosphere on the opening spread while maintaining readability, print efficiency, and clean PDF export for the body content.

- **Cover page**: Full dark background (`doc-surface-dark` #1C1610). Light text (`bone` #C4A882 for title, `iron` #8A7E6E for metadata). Pre-built as a template element with texture overlay.
- **Interior pages**: White or warm cream background (`doc-bg` or `doc-bg-warm`). Dark text (`doc-text` #1C1610). Rustpunk identity carried by typography, accent colors, heavy rules, and structural formatting.
- **Header band**: Dark background strip in the running header — a narrow band of `doc-surface-dark` with the document title in `bone` at 8pt Chakra Petch. Carries the dark aesthetic across every page.
- **Section dividers**: Full-width dark shaded paragraphs between major sections — `doc-surface-dark` background with light text in Chakra Petch.

**Why not full dark**: PDF export in Word drops page backgrounds by default. Word 365 Dark Mode creates a color inversion bug where "Automatic" text color exports as black on dark backgrounds. Full dark pages consume 5–10× more toner. ~47% of people have some degree of astigmatism that makes light-on-dark body text harder to read for extended periods.

## Template Architecture

Documents are built from a **pre-designed Word template** (.dotx or .docx) combined with **docx-js** for content injection and runtime styling.

**Lives in the template (designed once in Word):**
- Cover page layout with dark background, positioned text boxes, and texture watermark
- Header/footer design with dark banner, logo placement, and tab-stop alignment
- Watermark overlays (subtle concrete/noise texture at 5–8% opacity)
- Pre-built section divider images (distressed horizontal rules as thin PNG strips)
- Custom style definitions for all heading levels, callout boxes, and code containers

**Applied programmatically (docx-js or template rendering):**
- Text content injection into template placeholders
- Table construction with branded row styling (alternating fills, header shading)
- Cell and paragraph shading colors (via ShadingType.CLEAR)
- Font assignments, sizes, colors on runs
- Border weights and colors on paragraphs and table cells
- Conditional formatting (status colors, warning highlights)

**Critical constraint**: docx-js and python-docx cannot create text boxes, floating shapes, gradient fills, drawing objects, SmartArt, or complex watermarks. Any element requiring these must be pre-built in the template.

## Document Types

**Technical specifications** (e.g., Clinker Technical Spec): Dense, table-heavy, code-heavy. H1 for major sections (numbered: "1. Overview"), H2 for subsections (numbered: "1.1 Design Principles"), H3 for detail headers. Heavy use of parameter tables and code blocks.

**Guides and tutorials** (e.g., Clinker Mapping Guide): Progressive, example-driven. H1 for parts ("Part 1: Foundations"), H2 for scenarios (numbered: "Scenario 1: The 6-Line Convert"). Generous callout boxes for tips and warnings.

**Brand collateral and one-pagers**: Visual-first. Cover page IS the document. Minimal body text. Large pull quotes, full-width image bands, prominent maker's marks.

## Page Setup

| Property | Value | DXA |
|----------|-------|-----|
| Page size | US Letter (8.5" × 11") | 12240 × 15840 |
| Top margin | 1.0" | 1440 |
| Bottom margin | 1.0" | 1440 |
| Left margin | 1.25" | 1800 |
| Right margin | 1.0" | 1440 |
| Content width | 6.25" | 9000 |
| Header distance | 0.5" | 720 |
| Footer distance | 0.5" | 720 |

The asymmetric left margin (1.25" vs 1.0" right) is intentional — it creates subtle imbalance consistent with the rustpunk asymmetry principle, and provides binding clearance.

## Cover Page

Single section with no header/footer, dark background:

```
┌──────────────────────────────────────────┐
│  [texture overlay — subtle noise/grain]  │
│                                          │
│  DOCUMENT TITLE                          │  Saira Stencil One 36–48pt
│  // subtitle or tagline                  │  JetBrains Mono 11pt, oxide-red
│                                          │
│  ── rust line ──────────────────────     │  3pt oxide-red border
│                                          │
│  Version · Date · Status                 │  Chakra Petch 10pt, iron
│                                          │
│                      — Feed the kiln. —  │  JetBrains Mono 8pt, iron
└──────────────────────────────────────────┘
```

Text colors on dark cover: title in `bone` (#C4A882), tagline in `oxide-red` (#B7410E), metadata in `iron` (#8A7E6E). All text colors must be explicitly set — never use Word's "Automatic" color.

## Running Headers and Footers

**Header** (all interior pages):

```
┌──────────────────────────────────────────┐
│  CLINKER                    Technical Spec│  Dark band, Chakra Petch 8pt, bone
│──────────────────────────────────────────│  1pt oxide-red bottom border
```

Left-aligned: project name in ALL CAPS. Right-aligned (via tab stop): document type. Both in Chakra Petch 8pt, `bone` text on `doc-surface-dark` background. 1pt `oxide-red` bottom border.

Implementation: Use a dark-shaded paragraph in the header with tab stops. Not a table — tables in headers have minimum height issues.

```javascript
new Paragraph({
  shading: { fill: "1C1610", type: ShadingType.CLEAR },
  spacing: { after: 0 },
  border: { bottom: { style: BorderStyle.SINGLE, size: 8, color: "B7410E", space: 4 } },
  children: [
    new TextRun({ text: "CLINKER", font: "Chakra Petch", size: 16, color: "C4A882",
      bold: true, characterSpacing: 60 }),
    new TextRun({ text: "\tTechnical Specification", font: "Chakra Petch", size: 16,
      color: "8A7E6E" }),
  ],
  tabStops: [{ type: TabStopType.RIGHT, position: TabStopPosition.MAX }],
})
```

**Footer** (all interior pages):

Left-aligned: version, status, date in Chakra Petch 8pt, `doc-text-secondary`. Right-aligned: page number. Separated by 1pt `doc-border` top border.

## Heading Styles

All headings use Chakra Petch. Industrial character from weight, tracking, and structural punctuation.

**H1** — Chakra Petch 22pt, weight 600, ALL CAPS, color `doc-text` (#1C1610), expanded 2pt. 24pt before, 12pt after. Bottom border: 3pt `oxide-red`, 6pt space below.

**H2** — Chakra Petch 16pt, weight 600, ALL CAPS, color `doc-text`. 18pt before, 8pt after. No border.

**H3** — Chakra Petch 13pt, weight 500, ALL CAPS, color `oxide-red` (#B7410E), expanded 1pt. 14pt before, 6pt after.

**H4** — Chakra Petch 11pt, weight 500, color `doc-text`. Title Case (not ALL CAPS). 10pt before, 4pt after.

## Body Text

Calibri 11pt, `doc-text` (#1C1610), 1.15 line spacing (276 twentieths-of-a-line), 6pt space after paragraph. No first-line indent. Full justification for technical specs; left-aligned for guides.

## Tables

Every table follows this structure:

| Property | Value |
|----------|-------|
| Header background | `oxide-red` #B7410E |
| Header text | White #FFFFFF, Chakra Petch 10pt, 600 weight, ALL CAPS |
| Body text | Calibri 10pt, `doc-text` |
| Alternating row fill | White / `doc-surface` #F5F0E8 |
| Border color | `doc-border` #D4C9B8 |
| Border weight | 1pt (size 8 in docx-js half-points) |
| Cell padding | Top/bottom 80 DXA, left/right 120 DXA |
| Table width | Full content width (9000 DXA with spec margins) |

**Critical docx-js rule**: Use `ShadingType.CLEAR` for all cell shading, never `ShadingType.SOLID`. Each cell's shading must be a new object — reusing moves instead of copies.

```javascript
function headerCell(text, width) {
  return new TableCell({
    width: { size: width, type: WidthType.DXA },
    shading: { fill: "B7410E", type: ShadingType.CLEAR },
    borders: tableBorders,
    margins: { top: 80, bottom: 80, left: 120, right: 120 },
    children: [new Paragraph({
      children: [new TextRun({
        text: text, font: "Chakra Petch", size: 20, bold: true, color: "FFFFFF",
        characterSpacing: 40
      })]
    })]
  });
}

function bodyCell(text, width, isAlt) {
  return new TableCell({
    width: { size: width, type: WidthType.DXA },
    shading: { fill: isAlt ? "F5F0E8" : "FFFFFF", type: ShadingType.CLEAR },
    borders: tableBorders,
    margins: { top: 80, bottom: 80, left: 120, right: 120 },
    children: [new Paragraph({
      children: [new TextRun({ text: text, font: "Calibri", size: 20 })]
    })]
  });
}
```

## Code Blocks

Single-cell table container with accent left border:

| Property | Value |
|----------|-------|
| Container | Single-cell table, full content width |
| Background | `doc-surface` #F5F0E8 |
| Left border | 3pt `oxide-red` #B7410E |
| Other borders | 1pt `doc-border` #D4C9B8 |
| Font | JetBrains Mono 9.5pt, `doc-text` |
| Line spacing | Single (240 twentieths) |
| Cell padding | Top/bottom 120 DXA, left 200 DXA, right 120 DXA |
| Label | Chakra Petch 9pt, 500 weight, `doc-text-secondary`, ALL CAPS |

The label (language identifier: "YAML", "BASH", "JSON") is a separate paragraph inside the cell above the code content.

**Inline code**: JetBrains Mono 9.5pt with `doc-surface` background shading applied to the run (not the paragraph).

## Callout Boxes

Three callout types, each a single-cell table with colored left border and tinted background:

| Type | Left Border Color | Background | Label |
|------|-------------------|------------|-------|
| NOTE | `verdigris-dark` #2D7A76 | `#EDF7F6` | ℹ NOTE |
| WARNING | `hazard-dark` #9A6B00 | `#FFF8E6` | ⚠ WARNING |
| TIP | `oxide-red` #B7410E | `#FDF0EA` | ▸ TIP |

Structure: Chakra Petch 10pt label (600 weight, ALL CAPS, border color) followed by Calibri 10.5pt body text in `doc-text`. Left border 3pt, other borders 1pt `doc-border`.

```javascript
function noteCallout(labelText, bodyText) {
  return new Table({
    width: { size: 9000, type: WidthType.DXA },
    columnWidths: [9000],
    rows: [new TableRow({
      children: [new TableCell({
        width: { size: 9000, type: WidthType.DXA },
        shading: { fill: "EDF7F6", type: ShadingType.CLEAR },
        borders: {
          top: { style: BorderStyle.SINGLE, size: 8, color: "D4C9B8" },
          bottom: { style: BorderStyle.SINGLE, size: 8, color: "D4C9B8" },
          left: { style: BorderStyle.SINGLE, size: 24, color: "2D7A76" },
          right: { style: BorderStyle.SINGLE, size: 8, color: "D4C9B8" },
        },
        margins: { top: 120, bottom: 120, left: 200, right: 120 },
        children: [
          new Paragraph({
            spacing: { after: 80 },
            children: [new TextRun({
              text: "ℹ NOTE", font: "Chakra Petch", size: 20, bold: true,
              color: "2D7A76", characterSpacing: 60
            })]
          }),
          new Paragraph({
            children: [new TextRun({ text: bodyText, font: "Calibri", size: 21 })]
          })
        ]
      })]
    })]
  });
}
```

## Section Dividers

Between major sections (H1-level), insert a full-width dark divider — a paragraph with `doc-surface-dark` background. Text: "// SEC. 04" in Chakra Petch 10pt, `bone` color, expanded 1pt. Zero left/right indent (edge-to-edge within margins), 24pt space before and after.

For a lighter alternative, use the rust line (3pt `oxide-red` bottom border on an empty paragraph) between H2-level sections.

## Maker's Mark

Every document ends with the maker's mark. Last page, right-aligned, near the bottom:

```
                              — Feed the kiln. —
                              RUSTPUNK · v0.2 · 2026
```

JetBrains Mono 8pt, weight 300, `doc-text-secondary`. 48pt space before. Small, quiet, at the end — a foundry stamp on the underside of a cast part.

## Color Application (60-30-10 Rule)

- **60% — White/cream**: Page background, majority of cell fills, whitespace
- **30% — Dark neutrals**: Body text (`doc-text`), header bands, section dividers, cover page
- **10% — Accent colors**: Heading text in `oxide-red`, table headers, callout borders, code block borders

Within the 10% accent budget: ~5% `oxide-red`, ~3% `verdigris-dark` / `verdigris`, ~2% `hazard-dark` / `hazard`. Never combine multiple accent colors in a single table row, callout box, or heading.

## Status Indicators (Documents)

Rendered as inline text rather than bordered pills:

| Status | Text Color | Formatting |
|--------|-----------|-----------|
| DRAFT | `hazard-dark` #9A6B00 | Chakra Petch 10pt, ALL CAPS, bold |
| IN PROGRESS | `verdigris-dark` #2D7A76 | Chakra Petch 10pt, ALL CAPS, bold |
| RELEASED | `oxide-red` #B7410E | Chakra Petch 10pt, ALL CAPS, bold |
| DEPRECATED | `doc-text-secondary` #5C5043 | Chakra Petch 10pt, ALL CAPS, bold, strikethrough |

## Lists

Use Word's native numbering system (never unicode bullet characters). Bullet style: em dash (—) for unordered lists. Decimal for ordered lists.

```javascript
numbering: {
  config: [{
    reference: "rustpunk-bullets",
    levels: [{
      level: 0, format: LevelFormat.BULLET, text: "—",
      alignment: AlignmentType.LEFT,
      style: { paragraph: { indent: { left: 720, hanging: 360 } },
               run: { font: "Calibri" } }
    }, {
      level: 1, format: LevelFormat.BULLET, text: "▸",
      alignment: AlignmentType.LEFT,
      style: { paragraph: { indent: { left: 1440, hanging: 360 } },
               run: { font: "Calibri" } }
    }]
  }]
}
```

Level 0: em dash (—). Level 1: right-pointing triangle (▸). Level 2+: standard bullet (•).

## Document Variables Reference

These are reference values for programmatic document generation (docx-js, python-docx, template systems).

```
/* Document Palette */
doc-bg:              #FFFFFF
doc-bg-warm:         #FAF7F2
doc-surface:         #F5F0E8
doc-surface-dark:    #1C1610
doc-border:          #D4C9B8
doc-border-strong:   #B7410E (oxide-red)
doc-text:            #1C1610
doc-text-secondary:  #5C5043
doc-text-tertiary:   #8A7E6E
hazard-dark:         #9A6B00
verdigris-dark:      #2D7A76

/* Document Typography (pt / half-pt for docx-js size property) */
cover-title:         36–48pt / 72–96
h1:                  22pt / 44
h2:                  16pt / 32
h3:                  13pt / 26
h4:                  11pt / 22
body:                11pt / 22
code:                9.5pt / 19
table-header:        10pt / 20
table-body:          10pt / 20
callout-label:       10pt / 20
callout-body:        10.5pt / 21
footer:              8pt / 16
maker-mark:          8pt / 16

/* Document Spacing (DXA: 1440 = 1 inch, 20 = 1pt) */
h1-space-before:     480 (24pt)
h1-space-after:      240 (12pt)
h2-space-before:     360 (18pt)
h2-space-after:      160 (8pt)
h3-space-before:     280 (14pt)
h3-space-after:      120 (6pt)
body-space-after:    120 (6pt)
body-line-spacing:   276 (1.15 × 240)
section-gap:         480 (24pt)

/* Page Dimensions (DXA) */
page-width:          12240 (8.5")
page-height:         15840 (11")
margin-top:          1440 (1.0")
margin-bottom:       1440 (1.0")
margin-left:         1800 (1.25")
margin-right:        1440 (1.0")
content-width:       9000 (6.25")
```
