# VulnShield Design System

> This is a visual design reference, not a setup guide. Runtime, environment, and API instructions are maintained in the [root README](README.md). Implemented visual tokens and component behavior remain the source of truth in `packages/web`.

## Design Philosophy
Evidence-first diagnostic tool. Calm, confident, precise. Not alarmist. Reasoning chains as the visual signature.

---

## 1. COLOR TOKENS

### Core Palette
```
Background (page):       #0B0D10  (near-black, cool-blue tint)
Surface (cards/panels):  #14171B  (slightly lighter)
Border (hairline/divot): #262B31  (subtle structure)
Primary text:            #E8EAED  (off-white, high contrast)
Secondary text:          #8B92A0  (muted, for labels/hints)
Accent (interactive):    #5B8DEF  (calm precise blue – sparingly)
```

### Severity Colors (Functional only — never used decoratively elsewhere)
```
Critical:  #E5484D  (used in severity badges & risk metrics only)
High:      #F5A524  (used in severity badges & risk metrics only)
Medium:    #F5D90A  (used in severity badges & risk metrics only)
Low:       #4CC38A  (used in severity badges & risk metrics only)
```

### Derived/Utility
```
Success:      #4CC38A  (same as Low severity)
Error:        #E5484D  (same as Critical)
Warning:      #F5A524  (same as High)
Disabled:     #5A5F66  (muted interaction)
Focus ring:   #5B8DEF  (accent, 2px)
```

---

## 2. TYPOGRAPHY

### Font Stack
```
Display/Headings:  "Space Grotesk", sans-serif  (geometric, character)
Body/UI:           "Inter", sans-serif           (clean, humanist, readable)
Data/Evidence:     "IBM Plex Mono", monospace    (code, CVE-IDs, paths, scores)
```

### Type Scale
```
Display (H1):      36px, 600 weight, line-height 1.2  (landing hero title)
Heading 2 (H2):    28px, 600 weight, line-height 1.2  (section titles)
Heading 3 (H3):    20px, 600 weight, line-height 1.3  (card titles, metric labels)
Body (p):          16px, 400 weight, line-height 1.5  (reading copy)
Body Small:        14px, 400 weight, line-height 1.5  (labels, secondary info)
Caption:           12px, 400 weight, line-height 1.4  (footnotes, metadata)
Mono (data):       13px, 400 weight, line-height 1.5  (CVE-IDs, version strings, scores)
Mono (caption):    11px, 400 weight, line-height 1.4  (file paths, small data)
```

---

## 3. SPACING SYSTEM

```
xs:   4px
sm:   8px
md:   16px
lg:   24px
xl:   32px
xxl:  48px
```

Principle: Generous whitespace. Avoid cramming.

---

## 4. COMPONENTS & BORDERS

```
Border radius:
  sm:  2px    (hairline structure, diagnostic precision)
  md:  4px    (card corners, moderate visual softness)
  lg:  6px    (buttons, input fields)
  full: 9999px (pill shapes if needed)

Borders:
  Hairline (section dividers, structure):  1px solid #262B31
  Interactive (focus, hover):              2px solid #5B8DEF
  
Shadow:
  None — use borders and background layering instead (no drop shadows; minimalist)
```

---

## 5. INTERACTIVE ELEMENTS

### Buttons
```
Primary:    bg-#5B8DEF, text-#0B0D10, 14px Inter 600, px-16 py-10 (md rounded)
            hover: bg-#4A7FE0 (15% darker)
            active: scale(0.98), duration-75ms

Secondary:  bg-#14171B, text-#E8EAED, border-1px-#262B31
            hover: bg-#1C2128, border-#5B8DEF
            active: scale(0.98)

Danger:     bg-#E5484D, text-#FFFFFF, same sizing
            hover: bg-#D73F46

Ghost:      text-#5B8DEF, no bg/border
            hover: text-#4A7FE0, bg-rgba(91,141,239,0.08)
```

### Inputs
```
Border:       1px solid #262B31
Focus:        border-#5B8DEF, ring-2px-#5B8DEF, outline-none
Placeholder:  #5A5F66
Text:         #E8EAED
```

### Focus State
```
All interactive elements: ring-2px-offset-2px-#5B8DEF
```

---

## 6. SEVERITY BADGES

```
.badge-critical {
  background: rgba(229, 72, 77, 0.12);
  color: #E5484D;
  border-radius: 2px;
  padding: 4px 8px;
  font-size: 12px;
  font-weight: 600;
  font-family: "IBM Plex Mono";
}

(Same structure for high/medium/low with their respective colors)
```

---

## 7. LAYOUT GRID & SPACING

```
Page max-width:   1200px
Page padding:     24px (md) on sides, 32px (lg) vertical
Card padding:     24px
Section spacing:  48px (xxl) vertical between major sections
Hairline borders: Use #262B31, 1px, instead of cards/shadows
```

---

## 8. MOTION & REDUCED-MOTION

```
Default animations:
  fade-in:        duration-300ms, ease-in-out
  slide-in:       duration-300ms, ease-in-out
  color-change:   duration-200ms, ease-in-out

@media (prefers-reduced-motion: reduce):
  All animations: disabled (opacity 0 becomes instant show, no transition)
  
Reasoning chain step reveals: staggered fade-in, 150ms delay between steps
```

---

## 9. RESPONSIVE BREAKPOINTS

```
Mobile (xs):   < 640px
Tablet (md):   640px – 1024px
Desktop (lg):  > 1024px

RSIS gauge & knowledge graph: single column on mobile, reflow on desktop
Text sizing: body 16px throughout, caption 12px (no aggressive scaling)
```

---

## SIGNATURE ELEMENT: Reasoning Chain

```
Purpose: Visually distinguish the product's differentiator (chain of reasoning)
         from generic vulnerability scanners (which just list CVEs).

Structure:
  - Vertical connected flow (small numbered circles on left, lines between)
  - Each step shows two lines:
    • "Observed: [fact]"  (secondary text, 14px Inter 400)
    • "Deduced: [logic]"  (primary text, 14px Inter 600)
  - Evidence reference below in monospace (12px IBM Plex Mono, #8B92A0)

Usage:
  - Landing page: preview of 3–4 steps from an example scan (illustrative)
  - Analysis dashboard: full reasoning chain (all steps, live data)
  - Hover/focus: highlight individual step, show full evidence text in tooltip

Visual Treatment:
  - Circles: #5B8DEF (accent) with white number
  - Line: 1px solid #262B31 (hairline)
  - Step container: no background, just spacing (airy, not boxed)
  - Fade-in animation on load: steps reveal one at a time, 150ms between
```

---

# WIREFRAME: LANDING/HERO SECTION

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          VulnShield Header/Nav                               │
│  [Logo] VulnShield               [Home] [Docs] [GitHub]         [Sign In]   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                               │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                                                                       │   │
│  │  AI-Powered Vulnerability Detection & Remediation                   │   │
│  │  (Display/H1, "Space Grotesk", #E8EAED)                             │   │
│  │                                                                       │   │
│  │  Scan GitHub repositories with intelligent knowledge graphs         │   │
│  │  and LLM reasoning. Understand why each vulnerability matters.      │   │
│  │  (Body, "Inter", 16px, #8B92A0)                                     │   │
│  │                                                                       │   │
│  │  [Quick Scan]  [Full Analysis]                                      │   │
│  │   (Primary)    (Secondary button, accent border on hover)            │   │
│  │                                                                       │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                               │
│  ─────────────────────────────────────────────────────────────────────────  │
│  (hairline border #262B31)                                                   │
│                                                                               │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  What VulnShield Does: A Real Example                              │   │
│  │  (H2, "Space Grotesk", 28px, #E8EAED)                              │   │
│  │                                                                       │   │
│  │  Left Column (50% width on desktop, 100% on mobile):                │   │
│  │  ┌──────────────────────────────────────────────┐                  │   │
│  │  │ Scanned: lodash/lodash (CVE-2021-23337)     │                  │   │
│  │  │ RSIS Risk Score: 7.8                         │                  │   │
│  │  │ [███████░░] MEDIUM-HIGH                      │                  │   │
│  │  │                                               │                  │   │
│  │  │ Remediation: Update to lodash@4.17.21+       │                  │   │
│  │  │ Impact: Prevents prototype pollution in      │                  │   │
│  │  │         dependency graph.                     │                  │   │
│  │  └──────────────────────────────────────────────┘                  │   │
│  │  (Static example RSIS card, hairline borders, no shadow)            │   │
│  │                                                                       │   │
│  │  Right Column (50% width):                                          │   │
│  │                                                                       │   │
│  │  Reasoning Chain Preview:                                           │   │
│  │                                                                       │   │
│  │    ① Observed: lodash version 4.17.15 in package.json             │   │
│  │       Evidence: npm-parser found in dependency tree                │   │
│  │                                                                       │   │
│  │    ② Deduced: This version matches CVE-2021-23337                 │   │
│  │       Evidence: Cross-ref CISA KEV + GitHub Advisory               │   │
│  │                                                                       │   │
│  │    ③ Observed: Prototype pollution vulnerability in obj.assign()  │   │
│  │       Evidence: NVD description, CVSS 6.5                          │   │
│  │                                                                       │   │
│  │    ④ Deduced: Risk for this repo = MEDIUM-HIGH (7.8)              │   │
│  │       Evidence: Knowledge graph analysis, similar-repo scoring      │   │
│  │                                                                       │   │
│  │  (Each step shows as: circle with number, left-aligned line)        │   │
│  │  (Circles: #5B8DEF, lines: #262B31, text staggered fade-in)        │   │
│  │                                                                       │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                               │
│  ─────────────────────────────────────────────────────────────────────────  │
│  (hairline border)                                                           │
│                                                                               │
│  Why This Matters:                                                           │
│  (H2, 28px)                                                                  │
│                                                                               │
│  Most scanners list CVEs. VulnShield explains them.                         │
│  Built on reasoning chains, knowledge graphs, and LLM grounding.            │
│  Every finding is backed by evidence.                                        │
│  (Body copy, 16px, #8B92A0)                                                 │
│                                                                               │
│  [Learn More →]  (Ghost button, #5B8DEF text)                               │
│                                                                               │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## EXAMPLE COMPONENT CODE PATTERN

### Reasoning Chain Step (React/TSX pseudocode)
```tsx
<div className="reasoning-chain">
  {steps.map((step, idx) => (
    <div
      key={idx}
      className="step"
      style={{
        animation: `fadeIn 300ms ease-in-out ${idx * 150}ms backwards`,
      }}
    >
      <div className="step-number">{idx + 1}</div>
      <div className="step-line" />
      <div className="step-content">
        <p className="step-label">Observed:</p>
        <p className="step-text">{step.observed}</p>
        <p className="step-evidence">{step.evidence}</p>
        
        <p className="step-label">Deduced:</p>
        <p className="step-text">{step.deduced}</p>
      </div>
    </div>
  ))}
</div>
```

### Severity Badge Example
```tsx
<span className={`badge badge-${severity}`}>
  {severity.toUpperCase()}
</span>
```

---

## TAILWIND CONFIG STRUCTURE

All values defined as design tokens (not hardcoded):
- `colors`: All hex values mapped to semantic names
- `fontFamily`: Space Grotesk, Inter, IBM Plex Mono
- `fontSize`: Type scale (display, h2, h3, body, small, caption, mono, mono-sm)
- `spacing`: xs, sm, md, lg, xl, xxl
- `borderRadius`: sm, md, lg, full
- `borderColor`: base, focus
- `keyframes`: fadeIn, slideIn
- `animation`: Tied to reduced-motion

---

## CHECKLIST: What This Design Achieves

✓ Evidence-first: Monospace for facts, reasoning chains visible  
✓ Diagnostic tool feel: Hairlines, generous spacing, no drop shadows  
✓ Calm & confident: Accent color used sparingly (#5B8DEF), no neon  
✓ Signature element: Reasoning chain appears on landing & dashboard  
✓ Responsive: Hairlines scale with viewport, text doesn't shrink aggressively  
✓ Accessible: Respects reduced-motion, clear focus states, high contrast text  
✓ Coherent: All tokens centralized; dashboard components inherit system  
✓ Restrained: No decorative icons, no "feature grid" genericness  

---
