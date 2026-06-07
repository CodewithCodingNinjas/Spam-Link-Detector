"""
Reproducible SYNOPSIS.md -> SYNOPSIS.pdf generator.

Lightweight Markdown renderer (headings, paragraphs, bullet/numbered lists,
fenced code blocks, blockquotes, and pipe tables) built on fpdf2 so the PDF can
be regenerated deterministically whenever SYNOPSIS.md changes.

Usage:
    python tools/generate_synopsis_pdf.py
"""
import os
import re
from fpdf import FPDF

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MD = os.path.join(ROOT, "SYNOPSIS.md")
PDF = os.path.join(ROOT, "SYNOPSIS.pdf")


def _break_long_tokens(text: str, limit: int = 40) -> str:
    """Insert soft break opportunities into very long unbreakable tokens
    (e.g. URLs / DOIs) so multi_cell can wrap them instead of raising."""
    out = []
    for tok in text.split(" "):
        while len(tok) > limit:
            out.append(tok[:limit])
            tok = tok[limit:]
        out.append(tok)
    return " ".join(out)


def strip_inline(text: str) -> str:
    text = re.sub(r"\*\*(.+?)\*\*", r"\1", text)      # bold
    text = re.sub(r"(?<!\*)\*(?!\*)(.+?)\*", r"\1", text)  # italic
    text = re.sub(r"`(.+?)`", r"\1", text)            # inline code
    text = re.sub(r"\[(.+?)\]\((.+?)\)", r"\1 (\2)", text)  # links
    # Drop non-latin-1 glyphs (emoji etc.) that core fpdf fonts cannot encode
    text = text.encode("latin-1", "ignore").decode("latin-1")
    return _break_long_tokens(text)


class SynopsisPDF(FPDF):
    def header(self):
        pass

    def footer(self):
        self.set_y(-12)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(130)
        self.cell(0, 8, f"Page {self.page_no()}", align="C")
        self.set_text_color(0)


def render_table(pdf, rows):
    if not rows:
        return
    rows = [r for r in rows if not re.match(r"^[\s|:-]+$", r)]
    parsed = [[strip_inline(c.strip()) for c in r.strip().strip("|").split("|")]
              for r in rows]
    if not parsed:
        return
    ncol = max(len(r) for r in parsed)
    parsed = [(r + [""] * ncol)[:ncol] for r in parsed]
    pdf.set_x(pdf.l_margin)
    try:
        pdf.set_font("Helvetica", "", 8)
        with pdf.table(
            borders_layout="SINGLE_TOP_LINE",
            line_height=5,
            headings_style=__import__("fpdf").fonts.FontFace(emphasis="BOLD"),
            first_row_as_headings=True,
            width=pdf.w - pdf.l_margin - pdf.r_margin,
        ) as table:
            for row in parsed:
                trow = table.row()
                for cell in row:
                    trow.cell(cell)
        pdf.ln(2)
    except Exception:
        # Fallback: never hard-fail PDF generation on an awkward table.
        pdf.set_font("Helvetica", "", 8)
        for i, row in enumerate(parsed):
            pdf.set_x(pdf.l_margin)
            pdf.multi_cell(0, 4.5, ("  -  " if i else "  ") +
                           "  |  ".join(row))
        pdf.ln(2)


def main():
    with open(MD, "r", encoding="utf-8") as f:
        lines = f.read().splitlines()

    pdf = SynopsisPDF(format="A4")
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.set_margins(18, 16, 18)
    pdf.add_page()

    i = 0
    table_buf = []
    in_code = False

    def flush_table():
        nonlocal table_buf
        if table_buf:
            render_table(pdf, table_buf)
            table_buf = []

    while i < len(lines):
        raw = lines[i]
        line = raw.rstrip()

        if line.strip().startswith("```"):
            flush_table()
            in_code = not in_code
            if in_code:
                pdf.set_font("Courier", "", 8)
                pdf.set_fill_color(245)
            i += 1
            continue

        if in_code:
            pdf.set_x(pdf.l_margin)
            pdf.set_font("Courier", "", 7.5)
            pdf.multi_cell(0, 4.3, _break_long_tokens(
                line.encode("latin-1", "ignore").decode("latin-1"), 70) or " ",
                fill=True)
            i += 1
            continue

        if "|" in line and line.strip().startswith("|"):
            table_buf.append(line)
            i += 1
            continue
        else:
            flush_table()

        if not line.strip():
            pdf.ln(2)
            i += 1
            continue

        pdf.set_x(pdf.l_margin)  # always start a block at the left margin

        if line.startswith("# "):
            pdf.set_font("Helvetica", "B", 16)
            pdf.multi_cell(0, 8, strip_inline(line[2:]))
            pdf.ln(1)
        elif line.startswith("## "):
            pdf.ln(1)
            pdf.set_font("Helvetica", "B", 13)
            pdf.multi_cell(0, 7, strip_inline(line[3:]))
        elif line.startswith("### "):
            pdf.set_font("Helvetica", "B", 11)
            pdf.multi_cell(0, 6, strip_inline(line[4:]))
        elif line.strip() == "---":
            pdf.ln(1)
            pdf.set_draw_color(200)
            pdf.line(pdf.l_margin, pdf.get_y(), pdf.w - pdf.r_margin, pdf.get_y())
            pdf.ln(2)
        elif line.lstrip().startswith(("- ", "* ")):
            pdf.set_font("Helvetica", "", 9.5)
            pdf.multi_cell(0, 5, "  - " + strip_inline(line.lstrip()[2:]))
        elif re.match(r"^\s*\d+\.\s", line):
            pdf.set_font("Helvetica", "", 9.5)
            pdf.multi_cell(0, 5, "  " + strip_inline(line.strip()))
        elif line.startswith(">"):
            pdf.set_font("Helvetica", "I", 9)
            pdf.set_text_color(90)
            pdf.multi_cell(0, 5, strip_inline(line.lstrip("> ").rstrip()))
            pdf.set_text_color(0)
        else:
            pdf.set_font("Helvetica", "", 9.5)
            pdf.multi_cell(0, 5, strip_inline(line))
        i += 1

    flush_table()
    data = bytes(pdf.output())
    with open(PDF, "wb") as f:
        f.write(data)
    print(f"Wrote {PDF} ({pdf.page_no()} pages, {len(data)} bytes)")


if __name__ == "__main__":
    main()
