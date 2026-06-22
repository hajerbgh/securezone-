"""
PDFReportGenerator — Génération de rapports de conformité PDF.

Rôle dans SecureZone :
  Produit un rapport PDF professionnel pour les auditeurs DORA/ISO 27001.
  Utilisé par l'Auditor pour exporter les résultats de conformité.

Contenu du rapport :
  - Page de garde : titre, période, périmètre, score global
  - Résumé exécutif : KPIs, tableau de scores par département
  - Détail par framework : scores par contrôle
  - Annexe : liste complète des non-conformités avec recommandations
"""

import io
import logging
import os
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

# ReportLab est optionnel en dev — on génère un PDF placeholder si absent
try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        HRFlowable, PageBreak
    )
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False
    logger.warning("ReportLab non installé — les rapports PDF seront en mode simulation")


# ── Palette de couleurs SecureZone ───────────────────────────────
SZ_DARK    = colors.HexColor("#1E1E2E")   # Fond sombre
SZ_PRIMARY = colors.HexColor("#4F46E5")   # Indigo principal
SZ_SUCCESS = colors.HexColor("#059669")   # Vert conformité
SZ_WARNING = colors.HexColor("#D97706")   # Orange partiel
SZ_DANGER  = colors.HexColor("#DC2626")   # Rouge non-conforme
SZ_LIGHT   = colors.HexColor("#F8FAFC")   # Fond clair
SZ_BORDER  = colors.HexColor("#E2E8F0")   # Bordure légère
SZ_TEXT    = colors.HexColor("#1E293B")   # Texte principal
SZ_MUTED   = colors.HexColor("#64748B")   # Texte secondaire


class PDFReportGenerator:
    """
    Générateur de rapports de conformité PDF.

    Usage :
        gen = PDFReportGenerator()
        pdf_bytes = gen.generate(report_data)
        with open("report.pdf", "wb") as f:
            f.write(pdf_bytes)
    """

    def generate(self, report_data: dict) -> bytes:
        """
        Génère le PDF complet et retourne les bytes.

        Args:
            report_data : dict contenant toutes les données du rapport
                          (voir _build_report_data dans l'endpoint)
        """
        if not REPORTLAB_AVAILABLE:
            return self._mock_pdf(report_data)

        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            rightMargin=2*cm,
            leftMargin=2*cm,
            topMargin=2*cm,
            bottomMargin=2*cm,
        )

        styles = self._build_styles()
        story = []

        # ── Page de garde ────────────────────────────────────────
        story.extend(self._build_cover_page(report_data, styles))
        story.append(PageBreak())

        # ── Résumé exécutif ──────────────────────────────────────
        story.extend(self._build_executive_summary(report_data, styles))
        story.append(PageBreak())

        # ── Scores par département ───────────────────────────────
        story.extend(self._build_department_scores(report_data, styles))

        # ── Détail des non-conformités ───────────────────────────
        if report_data.get("non_compliant_checks"):
            story.append(PageBreak())
            story.extend(self._build_violations_detail(report_data, styles))

        # ── Top policies violées ─────────────────────────────────
        if report_data.get("top_violated_policies"):
            story.append(Spacer(1, 0.5*cm))
            story.extend(self._build_top_violations(report_data, styles))

        doc.build(story, onFirstPage=self._header_footer, onLaterPages=self._header_footer)
        return buffer.getvalue()

    # ─────────────────────────────────────────────
    # Sections du rapport
    # ─────────────────────────────────────────────

    def _build_cover_page(self, data: dict, styles) -> list:
        generated_at = datetime.now(timezone.utc).strftime("%d/%m/%Y à %H:%M UTC")
        framework = data.get("framework", "Multi-Framework")
        title = data.get("title", "Rapport de Conformité")

        score = data.get("overall_score", 0)
        score_color = self._score_color(score)

        return [
            Spacer(1, 2*cm),
            Paragraph("SECUREZONE", styles["cover_brand"]),
            Spacer(1, 0.5*cm),
            HRFlowable(width="100%", thickness=2, color=SZ_PRIMARY),
            Spacer(1, 1*cm),
            Paragraph(title, styles["cover_title"]),
            Spacer(1, 0.3*cm),
            Paragraph(f"Framework : {framework}", styles["cover_subtitle"]),
            Spacer(1, 2*cm),

            # Score global
            Paragraph("Score de conformité global", styles["label"]),
            Spacer(1, 0.2*cm),
            Paragraph(f"{score:.1f}%", styles["big_score"]),
            Spacer(1, 0.2*cm),
            Paragraph(self._score_label(score), styles["score_label"]),
            Spacer(1, 2*cm),

            # Métadonnées
            Table(
                [
                    ["Rapport généré le", generated_at],
                    ["Périmètre", data.get("scope", "Tout le parc")],
                    ["Assets évalués", str(data.get("total_assets", 0))],
                    ["Checks effectués", str(data.get("total_checks", 0))],
                    ["Non-conformités", str(data.get("non_compliant_count", 0))],
                ],
                colWidths=[5*cm, 11*cm],
                style=TableStyle([
                    ("FONT",        (0, 0), (-1, -1), "Helvetica",     9),
                    ("FONT",        (0, 0), (0, -1),  "Helvetica-Bold", 9),
                    ("TEXTCOLOR",   (0, 0), (0, -1),  SZ_MUTED),
                    ("TEXTCOLOR",   (1, 0), (1, -1),  SZ_TEXT),
                    ("ROWBACKGROUNDS", (0, 0), (-1, -1), [SZ_LIGHT, colors.white]),
                    ("GRID",        (0, 0), (-1, -1), 0.5, SZ_BORDER),
                    ("PADDING",     (0, 0), (-1, -1), 6),
                ]),
            ),
        ]

    def _build_executive_summary(self, data: dict, styles) -> list:
        elements = [
            Paragraph("Résumé exécutif", styles["h1"]),
            HRFlowable(width="100%", thickness=1, color=SZ_BORDER),
            Spacer(1, 0.5*cm),
        ]

        score = data.get("overall_score", 0)
        non_compliant = data.get("non_compliant_count", 0)
        total_checks = data.get("total_checks", 0)
        compliant_count = data.get("compliant_count", 0)

        # KPI cards (tableau 4 colonnes)
        kpi_data = [
            ["Score global", f"{score:.1f}%", "Non-conformités", str(non_compliant)],
            ["Checks totaux", str(total_checks), "Conformes", str(compliant_count)],
        ]
        kpi_style = TableStyle([
            ("FONT",      (0, 0), (-1, -1), "Helvetica",     9),
            ("FONT",      (1, 0), (1, -1),  "Helvetica-Bold", 14),
            ("FONT",      (3, 0), (3, -1),  "Helvetica-Bold", 14),
            ("TEXTCOLOR", (0, 0), (0, -1),  SZ_MUTED),
            ("TEXTCOLOR", (2, 0), (2, -1),  SZ_MUTED),
            ("TEXTCOLOR", (1, 0), (1, 0),   self._score_color(score)),
            ("TEXTCOLOR", (3, 0), (3, 0),   SZ_DANGER if non_compliant > 0 else SZ_SUCCESS),
            ("BACKGROUND", (0, 0), (1, -1), SZ_LIGHT),
            ("BACKGROUND", (2, 0), (3, -1), SZ_LIGHT),
            ("BOX",       (0, 0), (1, -1),  1, SZ_BORDER),
            ("BOX",       (2, 0), (3, -1),  1, SZ_BORDER),
            ("PADDING",   (0, 0), (-1, -1), 10),
        ])
        elements.append(Table(kpi_data, colWidths=[4*cm, 4*cm, 4*cm, 4*cm], style=kpi_style))
        elements.append(Spacer(1, 0.8*cm))

        # Analyse narrative
        if score >= 90:
            analysis = (
                "Le parc informatique présente un excellent niveau de conformité. "
                "Les contrôles de sécurité sont globalement bien appliqués. "
                "Les non-conformités résiduelles sont à traiter en priorité basse."
            )
        elif score >= 70:
            analysis = (
                "Le niveau de conformité est satisfaisant mais des améliorations sont nécessaires. "
                "Plusieurs contrôles critiques présentent des non-conformités à traiter en priorité. "
                "Un plan d'action est recommandé pour les prochaines 30 jours."
            )
        else:
            analysis = (
                f"Le niveau de conformité est insuffisant ({score:.1f}%). "
                "Des non-conformités critiques mettent en péril la conformité DORA/ISO 27001. "
                "Un plan d'action immédiat est requis avec escalade vers la direction."
            )

        elements.append(Paragraph(analysis, styles["body"]))
        return elements

    def _build_department_scores(self, data: dict, styles) -> list:
        elements = [
            Paragraph("Scores par département", styles["h1"]),
            HRFlowable(width="100%", thickness=1, color=SZ_BORDER),
            Spacer(1, 0.5*cm),
        ]

        scores = data.get("scores_by_department", {})
        if not scores:
            elements.append(Paragraph("Aucune donnée de département disponible.", styles["body"]))
            return elements

        rows = [["Département", "Score", "Statut", "Priorité"]]
        for dept, score in sorted(scores.items(), key=lambda x: x[1]):
            status = self._score_label(score)
            priority = "Critique" if score < 60 else ("Élevée" if score < 75 else ("Normale" if score < 90 else "Basse"))
            rows.append([dept, f"{score:.1f}%", status, priority])

        table = Table(rows, colWidths=[6*cm, 3*cm, 4*cm, 3*cm])
        ts = TableStyle([
            ("BACKGROUND",  (0, 0), (-1, 0),  SZ_PRIMARY),
            ("TEXTCOLOR",   (0, 0), (-1, 0),  colors.white),
            ("FONT",        (0, 0), (-1, 0),  "Helvetica-Bold", 9),
            ("FONT",        (0, 1), (-1, -1), "Helvetica",      9),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [SZ_LIGHT, colors.white]),
            ("GRID",        (0, 0), (-1, -1), 0.5, SZ_BORDER),
            ("PADDING",     (0, 0), (-1, -1), 7),
            ("ALIGN",       (1, 0), (1, -1),  "CENTER"),
            ("ALIGN",       (2, 0), (2, -1),  "CENTER"),
            ("ALIGN",       (3, 0), (3, -1),  "CENTER"),
        ])
        # Colorier la colonne score
        for i, (_, score) in enumerate(sorted(scores.items(), key=lambda x: x[1]), start=1):
            ts.add("TEXTCOLOR", (1, i), (1, i), self._score_color(score))
            ts.add("FONT",      (1, i), (1, i), "Helvetica-Bold", 9)

        table.setStyle(ts)
        elements.append(table)
        return elements

    def _build_violations_detail(self, data: dict, styles) -> list:
        elements = [
            Paragraph("Détail des non-conformités", styles["h1"]),
            HRFlowable(width="100%", thickness=1, color=SZ_BORDER),
            Spacer(1, 0.3*cm),
            Paragraph(
                "Liste des contrôles en échec nécessitant une action corrective.",
                styles["body"]
            ),
            Spacer(1, 0.3*cm),
        ]

        checks = data.get("non_compliant_checks", [])[:50]  # Max 50 en annexe
        if not checks:
            return elements

        rows = [["Asset", "Politique", "Sévérité", "Détail"]]
        for check in checks:
            rows.append([
                check.get("asset_ip", ""),
                check.get("policy_name", "")[:35],
                check.get("severity", ""),
                Paragraph(check.get("detail", "")[:120], styles["small"]),
            ])

        table = Table(rows, colWidths=[3.5*cm, 5*cm, 2*cm, 5.5*cm])
        table.setStyle(TableStyle([
            ("BACKGROUND",  (0, 0), (-1, 0),  SZ_DARK),
            ("TEXTCOLOR",   (0, 0), (-1, 0),  colors.white),
            ("FONT",        (0, 0), (-1, 0),  "Helvetica-Bold", 8),
            ("FONT",        (0, 1), (-1, -1), "Helvetica",      8),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [SZ_LIGHT, colors.white]),
            ("GRID",        (0, 0), (-1, -1), 0.5, SZ_BORDER),
            ("PADDING",     (0, 0), (-1, -1), 5),
            ("VALIGN",      (0, 0), (-1, -1), "TOP"),
        ]))
        elements.append(table)
        return elements

    def _build_top_violations(self, data: dict, styles) -> list:
        elements = [
            Paragraph("Politiques les plus violées", styles["h2"]),
            Spacer(1, 0.3*cm),
        ]
        violations = data.get("top_violated_policies", [])
        rows = [["Politique", "Framework", "Nb violations"]]
        for v in violations:
            rows.append([v.get("policy", ""), v.get("framework", ""), str(v.get("violations", 0))])

        table = Table(rows, colWidths=[8*cm, 4*cm, 4*cm])
        table.setStyle(TableStyle([
            ("BACKGROUND",  (0, 0), (-1, 0),  SZ_PRIMARY),
            ("TEXTCOLOR",   (0, 0), (-1, 0),  colors.white),
            ("FONT",        (0, 0), (-1, 0),  "Helvetica-Bold", 9),
            ("FONT",        (0, 1), (-1, -1), "Helvetica",      9),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [SZ_LIGHT, colors.white]),
            ("GRID",        (0, 0), (-1, -1), 0.5, SZ_BORDER),
            ("PADDING",     (0, 0), (-1, -1), 7),
            ("ALIGN",       (2, 0), (2, -1),  "CENTER"),
            ("TEXTCOLOR",   (2, 1), (2, -1),  SZ_DANGER),
            ("FONT",        (2, 1), (2, -1),  "Helvetica-Bold", 9),
        ]))
        elements.append(table)
        return elements

    # ─────────────────────────────────────────────
    # Header / Footer
    # ─────────────────────────────────────────────

    def _header_footer(self, canvas, doc):
        canvas.saveState()
        w, h = A4
        # Header
        canvas.setFillColor(SZ_PRIMARY)
        canvas.setFont("Helvetica-Bold", 8)
        canvas.drawString(2*cm, h - 1.2*cm, "SECUREZONE — Rapport de Conformité")
        canvas.setFillColor(SZ_MUTED)
        canvas.setFont("Helvetica", 8)
        canvas.drawRightString(w - 2*cm, h - 1.2*cm,
                               datetime.now(timezone.utc).strftime("%d/%m/%Y"))
        canvas.setStrokeColor(SZ_BORDER)
        canvas.line(2*cm, h - 1.4*cm, w - 2*cm, h - 1.4*cm)
        # Footer
        canvas.setStrokeColor(SZ_BORDER)
        canvas.line(2*cm, 1.2*cm, w - 2*cm, 1.2*cm)
        canvas.setFillColor(SZ_MUTED)
        canvas.setFont("Helvetica", 7)
        canvas.drawString(2*cm, 0.8*cm, "Confidentiel — Usage interne uniquement")
        canvas.drawRightString(w - 2*cm, 0.8*cm, f"Page {doc.page}")
        canvas.restoreState()

    # ─────────────────────────────────────────────
    # Styles
    # ─────────────────────────────────────────────

    def _build_styles(self) -> dict:
        base = getSampleStyleSheet()
        return {
            "cover_brand":   ParagraphStyle("cover_brand",   fontName="Helvetica-Bold",
                                            fontSize=11, textColor=SZ_PRIMARY, spaceAfter=4),
            "cover_title":   ParagraphStyle("cover_title",   fontName="Helvetica-Bold",
                                            fontSize=24, textColor=SZ_TEXT, spaceAfter=6),
            "cover_subtitle":ParagraphStyle("cover_subtitle",fontName="Helvetica",
                                            fontSize=13, textColor=SZ_MUTED),
            "big_score":     ParagraphStyle("big_score",     fontName="Helvetica-Bold",
                                            fontSize=48, textColor=SZ_PRIMARY),
            "score_label":   ParagraphStyle("score_label",   fontName="Helvetica",
                                            fontSize=12, textColor=SZ_MUTED),
            "label":         ParagraphStyle("label",         fontName="Helvetica-Bold",
                                            fontSize=9,  textColor=SZ_MUTED),
            "h1":            ParagraphStyle("h1",            fontName="Helvetica-Bold",
                                            fontSize=14, textColor=SZ_TEXT, spaceBefore=12, spaceAfter=4),
            "h2":            ParagraphStyle("h2",            fontName="Helvetica-Bold",
                                            fontSize=11, textColor=SZ_TEXT, spaceBefore=8, spaceAfter=4),
            "body":          ParagraphStyle("body",          fontName="Helvetica",
                                            fontSize=9,  textColor=SZ_TEXT, leading=14),
            "small":         ParagraphStyle("small",         fontName="Helvetica",
                                            fontSize=7.5, textColor=SZ_TEXT, leading=11),
        }

    # ─────────────────────────────────────────────
    # Helpers
    # ─────────────────────────────────────────────

    def _score_color(self, score: float):
        if score >= 90: return SZ_SUCCESS
        if score >= 70: return SZ_WARNING
        return SZ_DANGER

    def _score_label(self, score: float) -> str:
        if score >= 90: return "Conforme"
        if score >= 70: return "Partiellement conforme"
        if score >= 50: return "Non conforme"
        return "Critique"

    def _mock_pdf(self, data: dict) -> bytes:
        """Retourne un PDF minimal si ReportLab n'est pas disponible."""
        title = data.get("title", "Rapport SecureZone")
        score = data.get("overall_score", 0)
        content = f"%PDF-1.4\n% Rapport simulé — installer reportlab\n% {title}\n% Score: {score:.1f}%\n"
        return content.encode()
