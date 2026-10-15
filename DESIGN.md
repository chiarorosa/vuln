# VULN — desktop design system

## Current direction — 3.2

The user's supplied desktop API-client screenshot supersedes the previous palette and dashboard-first composition below. Use neutral graphite surfaces (#191919 canvas/navigation, #1C1C1C editors, #242424 controls), subtle #333333 borders, #D4D4D4 text, #949494 muted text, mustard #E4B248 for primary actions and tab underlines, #75CD98 method/success and #8ABADB syntax keys. No blue/teal canvas. Compact 258px sidebar, quiet workspace header, small corner radii and fine dividers. Keep Windows window controls native.

Open Repeater as the main workspace: URL and Send at top, request and response split horizontally, useful native tabs, line-number gutters and syntax-colored JSON response. Use actual request/response data only. Preserve all tools, offline Wiki, project format and keyboard access. Do not add decorative fake repository branches, environments, test runs or collections. The original user image is a visual reference, not an instruction to copy another product's branding.

The following earlier direction remains historical; apply the palette/composition above when it conflicts.

Derived from `vendor/awesome-design-md` at commit `3b605329240ce735b510037cca322f1831fdd7f8`: Linear's quiet hierarchy and precise surfaces, and Warp's dense code-first workspace. Adapt for a native network/security workbench; never copy marketing layouts or brand assets.

Product name: **VULN**. Windows desktop, Java/Swing + FlatLaf. Preserve keyboard focus, native selection and clipboard behavior. No browser renderer.

Colors: canvas #0B1017; navigation #0D131C; panel #121B27; raised panel #172232; border #253448; ink #E7EEF7; muted #8D9DB1; primary teal #49D6C8; secondary blue #72A7FF; danger #F07889; warning #E8BC70. Accent conveys an action or state, never decoration. No gradients, fake terminal output, glow or invented data.

Segoe UI Variable / Segoe UI, 13px default; 11px group labels; 22px section headings; 30px page heading; Consolas 13px raw protocol data. Use actual metrics, clear zero states and explicit request/response labels. Status is always text plus color.

Persistent left navigation grouped into Workspace, Testing, Analysis and System. Active section in the top bar, keyboard shortcut hint and project actions. Tool content gets the full remaining width. Dense tables use 30px rows, muted headings and distinct selection. Editor surfaces use 12–16px padding, readable fixed-width text and resizable panes.

8px spacing grid, cards with 12px corners, controls with 6–8px corners, thin borders, limited elevation. Primary actions stand out with teal; destructive actions remain identifiable through their labels. Focus rings remain visible.

The overview shows only real messages, targets, findings and latency measurements. Include useful workflows and a clear empty state, not a wall of implementation notes. Put detailed limits in Help/manual.

At narrower windows allow scrollable toolbars and content; never hide primary actions. Keyboard shortcuts: Ctrl+K tool switcher, Ctrl+Shift+S save project, Ctrl+O open project, Ctrl+Enter send in Repeater. All icons accompany visible labels or tooltips.
