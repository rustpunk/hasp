# Anti-Patterns

## Web Anti-Patterns

- **No cursive or script fonts.** Ever.
- **No purple gradients.** Fastest way to look like generic AI output.
- **No border-radius above 4px.** Rustpunk is angular.
- **No white backgrounds.** Lightest surface is `char-raised` (#14110C).
- **No bright white text.** Maximum brightness is `bone` (#C4A882).
- **No uniform symmetry.** If all four card corners are identical, break one.
- **No hover scale/bounce animations.** Things hold steady or flicker.
- **No emoji.** Use monospace symbols (→, //, ×, ✓, ▊) or SVG marks.
- **No gradient text.** Text is solid color. Gradients go on dividers and backgrounds.
- **No stock photography or illustrations.** SVG diagrams, patterns, and texture only.
- **No text below #5C4A30 on dark backgrounds.** Contrast floor.
- **No mixing sub-aesthetic accent families in the same component.**

## Document Anti-Patterns

- **No full dark page backgrounds on interior pages.** Cover page only. PDF export, printing, and accessibility all fail.
- **No "Automatic" text color in Word.** Always set explicit RGB. Automatic exports as black regardless of background.
- **No `ShadingType.SOLID` in docx-js.** Always use `ShadingType.CLEAR`. SOLID renders as black in many viewers.
- **No `WidthType.PERCENTAGE` for tables.** Always use `WidthType.DXA`. Percentages break in Google Docs.
- **No synthetic bold on Saira Stencil One.** It's a single-weight font. Use it at 400 only.
- **No JetBrains Mono for body text in documents.** Monospace body text is fatiguing for extended reading. Use Calibri for body, JetBrains Mono for code only.
- **No `hazard` (#E8A524) or `verdigris` (#43B3AE) as text on white.** They fail WCAG AA. Use the darkened variants for text, originals for backgrounds only.
- **No tables as horizontal rules in headers/footers.** Cells have minimum height and render as empty boxes. Use paragraph borders instead.
- **No unicode bullet characters (•, ▪).** Use Word's native `LevelFormat.BULLET` with numbering config.
- **No text boxes, floating shapes, or gradient fills generated programmatically.** These must be pre-built in the Word template. docx-js and python-docx cannot create them reliably.
- **No centered body text.** Left-align or justify. Centered text reads as polished and designed — antithetical to the aesthetic.
- **No decorative fonts for body.** Chakra Petch is for headings and labels. Body text is Calibri. Code is JetBrains Mono. Respect the hierarchy.

## Document Textures

Noise overlays, scanlines, and CSS-based textures cannot be reproduced programmatically in .docx. These are handled through **pre-built template assets** — designed once, baked into the Word template, and left untouched by code.
