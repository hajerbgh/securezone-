"""
Reports — Génération de rapports PDF professionnels.

GET /api/v1/reports/executive   → Rapport exécutif (management / CISO)
GET /api/v1/reports/technical   → Rapport technique complet (SOC engineers)
GET /api/v1/reports/compliance  → Rapport de conformité (ISO 27001 / DORA / CIS)
"""

import html
import io
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.db.session import get_db
from app.models.alert import Alert, AlertSeverity, AlertStatus, AlertCategory
from app.models.vulnerability import Vulnerability, VulnSeverity, ScanJob
from app.models.asset import Asset
from app.models.compliance import HardeningPolicy, ComplianceCheck, ComplianceStatus
from app.api.deps import get_current_user
from app.models.user import User

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable, KeepTogether,
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT

logger = logging.getLogger(__name__)
router = APIRouter(tags=["Rapports"])

# ── Dimensions ────────────────────────────────────────────────────────────────
W, H = A4                          # 595.28 × 841.89 pt  (A4)
MARGIN = 2 * cm                    # marges gauche / droite
CONTENT_W = W - 2 * MARGIN        # ~481 pt ≈ 17 cm

# ── Palette ───────────────────────────────────────────────────────────────────
_c = colors.HexColor

BRAND      = _c('#4F46E5')
DARK       = _c('#0F172A')
SLATE      = _c('#1E293B')
CARD_BG    = _c('#F8FAFC')
BORDER     = _c('#E2E8F0')
TEXT_C     = _c('#1E293B')
MUTED_C    = _c('#64748B')

# Sévérité — objets reportlab + hex string pour Paragraph XML
C_CRIT, H_CRIT   = _c('#DC2626'), '#DC2626'
C_HIGH, H_HIGH   = _c('#EA580C'), '#EA580C'
C_MED,  H_MED    = _c('#D97706'), '#D97706'
C_LOW,  H_LOW    = _c('#16A34A'), '#16A34A'
C_OK,   H_OK     = _c('#0F766E'), '#0F766E'
C_INFO, H_INFO   = _c('#0284C7'), '#0284C7'
C_MUTED,H_MUTED  = _c('#94A3B8'), '#94A3B8'

SEV_MAP = {
    'critical': (C_CRIT, H_CRIT, 'CRITIQUE'),
    'high':     (C_HIGH, H_HIGH, 'ÉLEVÉE'),
    'medium':   (C_MED,  H_MED,  'MOYENNE'),
    'low':      (C_LOW,  H_LOW,  'FAIBLE'),
    'info':     (C_INFO, H_INFO, 'INFO'),
    'none':     (C_MUTED,H_MUTED,'—'),
}

MONTHS_FR = {
    1: 'janvier', 2: 'février',  3: 'mars',      4: 'avril',
    5: 'mai',     6: 'juin',     7: 'juillet',    8: 'août',
    9: 'septembre',10:'octobre', 11: 'novembre', 12: 'décembre',
}

STATUS_LABELS = {
    'open': 'Ouverte', 'investigating': 'En cours', 'resolved': 'Résolue',
    'false_positive': 'Faux positif', 'suppressed': 'Supprimée',
    'in_remediation': 'En remédiation', 'patched': 'Corrigée',
    'accepted_risk': 'Risque accepté', 'compliant': 'Conforme',
    'non_compliant': 'Non conforme', 'partially_compliant': 'Partiel',
    'not_checked': 'Non vérifié', 'pending': 'En attente',
    'running': 'En cours', 'completed': 'Terminé', 'failed': 'Échoué',
    'online': 'En ligne', 'offline': 'Hors ligne', 'unknown': 'Inconnu',
}

FW_LABELS = {
    'iso_27001': 'ISO 27001', 'dora': 'DORA',
    'cis': 'CIS Controls', 'custom': 'Personnalisé',
}


def _fr_date(dt: datetime) -> str:
    return f"{dt.day} {MONTHS_FR[dt.month]} {dt.year} à {dt.strftime('%H:%M')} UTC"


def _e(s) -> str:
    """Échappe les caractères XML pour Paragraph."""
    return html.escape(str(s) if s is not None else '—')


def _sev_xml(sev: str) -> str:
    _, h, label = SEV_MAP.get(sev, (C_MUTED, H_MUTED, sev.upper()))
    return f'<font color="{h}"><b>{label}</b></font>'


def _status_label(s: str) -> str:
    return STATUS_LABELS.get(s, s.replace('_', ' ').title())


# ── Styles Platypus ───────────────────────────────────────────────────────────
def _make_styles() -> dict:
    base = getSampleStyleSheet()
    N = base['Normal']
    return {
        # ── Cover ──
        'cover_logo':  ParagraphStyle('cl',  parent=N, fontName='Helvetica-Bold',
                                      fontSize=11, textColor=BRAND, spaceAfter=3),
        'cover_sup':   ParagraphStyle('cs',  parent=N, fontName='Helvetica',
                                      fontSize=7.5, textColor=_c('#475569'), spaceAfter=22),
        'cover_title': ParagraphStyle('ct',  parent=N, fontName='Helvetica-Bold',
                                      fontSize=28, leading=34, textColor=colors.white, spaceAfter=10),
        'cover_sub':   ParagraphStyle('csu', parent=N, fontName='Helvetica',
                                      fontSize=13, leading=18, textColor=_c('#94A3B8'), spaceAfter=4),
        'cover_meta':  ParagraphStyle('cm',  parent=N, fontName='Helvetica',
                                      fontSize=9, leading=13, textColor=_c('#64748B'), spaceAfter=2),
        'cover_badge': ParagraphStyle('cb',  parent=N, fontName='Helvetica-Bold',
                                      fontSize=9, textColor=C_CRIT),
        # ── Sections ──
        'sec_h':   ParagraphStyle('sh',  parent=N, fontName='Helvetica-Bold',
                                  fontSize=13, leading=16, textColor=colors.white),
        'sub_h':   ParagraphStyle('sbh', parent=N, fontName='Helvetica-Bold',
                                  fontSize=10, leading=14, textColor=SLATE,
                                  spaceBefore=14, spaceAfter=5),
        # ── Corps ──
        'body':    ParagraphStyle('bd',  parent=N, fontName='Helvetica',
                                  fontSize=9, leading=13, textColor=TEXT_C, spaceAfter=3),
        'note':    ParagraphStyle('nt',  parent=N, fontName='Helvetica',
                                  fontSize=8, leading=11, textColor=MUTED_C, spaceAfter=4),
        # ── Cellules de table ──
        'cell':    ParagraphStyle('c',   parent=N, fontName='Helvetica',
                                  fontSize=8, leading=10, textColor=TEXT_C),
        'cell_b':  ParagraphStyle('cb2', parent=N, fontName='Helvetica-Bold',
                                  fontSize=8, leading=10, textColor=TEXT_C),
        'cell_m':  ParagraphStyle('cm2', parent=N, fontName='Helvetica',
                                  fontSize=8, leading=10, textColor=MUTED_C),
        # ── KPI ──
        'kpi_v':   ParagraphStyle('kv',  parent=N, fontName='Helvetica-Bold',
                                  fontSize=22, leading=26, alignment=TA_CENTER),
        'kpi_l':   ParagraphStyle('kl',  parent=N, fontName='Helvetica',
                                  fontSize=8, leading=10, textColor=MUTED_C, alignment=TA_CENTER),
    }


# ── Canvas callbacks ───────────────────────────────────────────────────────────
def _cb_cover(canvas, doc):
    """Page de couverture : fond sombre + barre bleue latérale."""
    canvas.saveState()
    canvas.setFillColor(DARK)
    canvas.rect(0, 0, W, H, fill=1, stroke=0)
    canvas.setFillColor(BRAND)
    canvas.rect(0, 0, 0.45 * cm, H, fill=1, stroke=0)  # barre gauche
    canvas.rect(0, 0, W, 0.3 * cm, fill=1, stroke=0)   # barre basse
    canvas.restoreState()


def _make_page_cb(title: str, date_str: str):
    """Callback header/footer pour les pages 2+."""
    def _cb(canvas, doc):
        canvas.saveState()
        # ── Header ──
        canvas.setFillColor(BRAND)
        canvas.rect(0, H - 1.3 * cm, W, 1.3 * cm, fill=1, stroke=0)
        canvas.setFillColor(colors.white)
        canvas.setFont('Helvetica-Bold', 8)
        canvas.drawString(MARGIN, H - 0.82 * cm, 'SecureZone')
        canvas.setFont('Helvetica', 8)
        canvas.drawString(MARGIN + 2.4 * cm, H - 0.82 * cm, f'— {title}')
        canvas.setFont('Helvetica', 7.5)
        canvas.drawRightString(W - MARGIN, H - 0.82 * cm, f'CONFIDENTIEL  ·  {date_str}')
        # ── Footer ──
        canvas.setFillColor(SLATE)
        canvas.rect(0, 0, W, 0.65 * cm, fill=1, stroke=0)
        canvas.setFillColor(colors.white)
        canvas.setFont('Helvetica', 7)
        canvas.drawString(MARGIN, 0.2 * cm, 'Document confidentiel — Usage interne uniquement — Ne pas diffuser')
        canvas.drawRightString(W - MARGIN, 0.2 * cm, f'Page {canvas.getPageNumber()}')
        canvas.restoreState()
    return _cb


# ── Composants réutilisables ──────────────────────────────────────────────────
def _cover_page(type_label: str, subtitle: str, user_name: str,
                date_str: str, st: dict) -> list:
    elems = [Spacer(1, 3.8 * cm)]
    elems.append(Paragraph('SecureZone', st['cover_logo']))
    elems.append(Paragraph('UNIFIED SECURITY PLATFORM', st['cover_sup']))
    elems.append(HRFlowable(width='100%', thickness=2, color=BRAND, spaceAfter=20))
    elems.append(Paragraph(type_label, st['cover_title']))
    elems.append(Paragraph(subtitle, st['cover_sub']))
    elems.append(Spacer(1, 1.5 * cm))
    for line in [f'Date : {date_str}', f'Généré par : {user_name}',
                 'Plateforme : SecureZone — Unified Security Platform']:
        elems.append(Paragraph(line, st['cover_meta']))
    elems.append(Spacer(1, 1 * cm))
    elems.append(HRFlowable(width='100%', thickness=0.5, color=_c('#334155'), spaceAfter=10))
    elems.append(Paragraph('⚠ CONFIDENTIEL — Document à usage interne uniquement', st['cover_badge']))
    elems.append(PageBreak())
    return elems


def _section(title: str, st: dict) -> list:
    tbl = Table([[Paragraph(title, st['sec_h'])]], colWidths=[CONTENT_W])
    tbl.setStyle(TableStyle([
        ('BACKGROUND',    (0, 0), (-1, -1), BRAND),
        ('LEFTPADDING',   (0, 0), (-1, -1), 10),
        ('RIGHTPADDING',  (0, 0), (-1, -1), 10),
        ('TOPPADDING',    (0, 0), (-1, -1), 7),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 7),
    ]))
    return [Spacer(1, 0.5 * cm), tbl, Spacer(1, 0.3 * cm)]


def _kpi_row(items: list, st: dict) -> Table:
    """items = [(valeur, libellé, hex_couleur), ...]"""
    cw = CONTENT_W / len(items)
    top = [Paragraph(f'<font color="{h}"><b>{_e(v)}</b></font>', st['kpi_v'])
           for v, _, h in items]
    bot = [Paragraph(_e(lbl), st['kpi_l']) for _, lbl, _ in items]
    tbl = Table([top, bot], colWidths=[cw] * len(items))
    tbl.setStyle(TableStyle([
        ('BACKGROUND',    (0, 0), (-1, -1), CARD_BG),
        ('BOX',           (0, 0), (-1, -1), 1, BORDER),
        ('LINEAFTER',     (0, 0), (-2, -1), 0.5, BORDER),
        ('TOPPADDING',    (0, 0), (-1, 0),  14),
        ('BOTTOMPADDING', (0, 0), (-1, 0),  2),
        ('TOPPADDING',    (0, 1), (-1, 1),  2),
        ('BOTTOMPADDING', (0, 1), (-1, 1),  12),
        ('ALIGN',         (0, 0), (-1, -1), 'CENTER'),
        ('VALIGN',        (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    return tbl


def _dtable(headers: list, rows: list, col_widths: list) -> Table:
    """Table de données avec header foncé et lignes alternées."""
    all_rows = [headers] + rows
    tbl = Table(all_rows, colWidths=col_widths, repeatRows=1)
    alt = [('BACKGROUND', (0, i), (-1, i), CARD_BG)
           for i in range(2, len(all_rows), 2)]
    tbl.setStyle(TableStyle([
        # ── Header ──
        ('BACKGROUND',    (0, 0), (-1, 0), SLATE),
        ('TEXTCOLOR',     (0, 0), (-1, 0), colors.white),
        ('FONTNAME',      (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE',      (0, 0), (-1, 0), 8),
        ('TOPPADDING',    (0, 0), (-1, 0), 7),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 7),
        # ── Corps ──
        ('FONTNAME',      (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE',      (0, 1), (-1, -1), 8),
        ('TOPPADDING',    (0, 1), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 1), (-1, -1), 5),
        # ── Commun ──
        ('LEFTPADDING',   (0, 0), (-1, -1), 8),
        ('RIGHTPADDING',  (0, 0), (-1, -1), 8),
        ('VALIGN',        (0, 0), (-1, -1), 'MIDDLE'),
        ('LINEBELOW',     (0, 0), (-1, -1), 0.5, BORDER),
        ('LINEAFTER',     (0, 0), (-2, -1), 0.5, BORDER),
        *alt,
    ]))
    return tbl


# ── Collecte des données ──────────────────────────────────────────────────────
async def _collect(db: AsyncSession) -> dict:
    now = datetime.now(timezone.utc)

    def _val(row_or_col):
        return row_or_col.value if hasattr(row_or_col, 'value') else str(row_or_col)

    # ── Alertes ──
    a_sev = {_val(r[0]): r[1] for r in (await db.execute(
        select(Alert.severity, func.count(Alert.id)).group_by(Alert.severity)
    )).all()}
    a_stat = {_val(r[0]): r[1] for r in (await db.execute(
        select(Alert.status, func.count(Alert.id)).group_by(Alert.status)
    )).all()}
    a_cat = {_val(r[0]): r[1] for r in (await db.execute(
        select(Alert.category, func.count(Alert.id))
        .group_by(Alert.category)
        .order_by(func.count(Alert.id).desc())
    )).all()}

    crit_q = (await db.execute(
        select(Alert)
        .where(Alert.severity.in_([AlertSeverity.CRITICAL, AlertSeverity.HIGH]))
        .order_by(Alert.created_at.desc()).limit(15)
    )).scalars().all()

    all_a_q = (await db.execute(
        select(Alert).order_by(Alert.created_at.desc()).limit(60)
    )).scalars().all()

    def _alert_dict(a, title_max=70):
        t = a.title
        return {
            'id': a.id,
            'title': (t[:title_max] + '…') if len(t) > title_max else t,
            'severity': _val(a.severity),
            'category': _val(a.category).replace('_', ' ').title(),
            'status': _val(a.status),
            'source_ip': a.source_ip or '—',
            'mitre': a.mitre_technique_id or '—',
            'date': a.created_at.strftime('%d/%m/%Y %H:%M') if a.created_at else '—',
        }

    # ── Vulnérabilités ──
    v_sev = {_val(r[0]): r[1] for r in (await db.execute(
        select(Vulnerability.severity, func.count(Vulnerability.id))
        .group_by(Vulnerability.severity)
    )).all()}
    v_stat = {_val(r[0]): r[1] for r in (await db.execute(
        select(Vulnerability.status, func.count(Vulnerability.id))
        .group_by(Vulnerability.status)
    )).all()}

    top_v_q = (await db.execute(
        select(Vulnerability, Asset.ip_address, Asset.hostname)
        .join(Asset, Vulnerability.asset_id == Asset.id)
        .where(Vulnerability.severity.in_([VulnSeverity.CRITICAL, VulnSeverity.HIGH]))
        .order_by(Vulnerability.cvss_score.desc().nullslast())
        .limit(20)
    )).all()

    all_v_q = (await db.execute(
        select(Vulnerability, Asset.ip_address, Asset.hostname)
        .join(Asset, Vulnerability.asset_id == Asset.id)
        .order_by(Vulnerability.cvss_score.desc().nullslast(),
                  Vulnerability.created_at.desc())
        .limit(100)
    )).all()

    def _vuln_dict(v, ip, host, title_max=55):
        t = v.title
        return {
            'cve_id': v.cve_id or '—',
            'title': (t[:title_max] + '…') if len(t) > title_max else t,
            'severity': _val(v.severity),
            'cvss': f'{v.cvss_score:.1f}' if v.cvss_score else '—',
            'asset': f'{ip}' + (f' ({host})' if host else ''),
            'service': f"{v.affected_service or '—'}:{v.affected_port or ''}".rstrip(':'),
            'status': _val(v.status),
            'solution': (v.solution or '')[:90],
        }

    # ── Assets ──
    total_assets = await db.scalar(select(func.count(Asset.id))) or 0
    a_stat_asset = {_val(r[0]): r[1] for r in (await db.execute(
        select(Asset.status, func.count(Asset.id)).group_by(Asset.status)
    )).all()}
    asset_list_q = (await db.execute(
        select(Asset).order_by(Asset.created_at.desc()).limit(50)
    )).scalars().all()

    def _asset_dict(a):
        crit = getattr(a, 'criticality', None)
        return {
            'ip': a.ip_address,
            'hostname': a.hostname or '—',
            'os': a.os_name or '—',
            'status': _val(a.status),
            'criticality': _val(crit) if crit else 'medium',
            'ports': len(a.open_ports or []),
        }

    # ── Conformité ──
    policies_q = (await db.execute(
        select(HardeningPolicy).where(HardeningPolicy.is_active == True)
    )).scalars().all()

    c_stat = {_val(r[0]): r[1] for r in (await db.execute(
        select(ComplianceCheck.status, func.count(ComplianceCheck.id))
        .group_by(ComplianceCheck.status)
    )).all()}
    total_checks = sum(c_stat.values())
    compliant = c_stat.get('compliant', 0)
    global_score = round((compliant / total_checks) * 100, 1) if total_checks else 0.0

    frameworks: dict[str, list] = {}
    for p in policies_q:
        fw = _val(p.framework)
        frameworks.setdefault(fw, []).append({
            'control_id': p.control_id or '—',
            'name': p.name,
            'severity': _val(p.severity),
            'rule_type': p.rule_type,
        })

    # ── Scans récents ──
    scans_q = (await db.execute(
        select(ScanJob).order_by(ScanJob.created_at.desc()).limit(5)
    )).scalars().all()

    return {
        'now': now,
        'alerts': {
            'total': sum(a_sev.values()),
            'open': a_stat.get('open', 0) + a_stat.get('investigating', 0),
            'by_sev': a_sev,
            'by_status': a_stat,
            'by_cat': a_cat,
            'critical_list': [_alert_dict(a) for a in crit_q],
            'all': [_alert_dict(a, 60) for a in all_a_q],
        },
        'vulns': {
            'total': sum(v_sev.values()),
            'open': v_stat.get('open', 0),
            'by_sev': v_sev,
            'by_status': v_stat,
            'top': [_vuln_dict(v, ip, h) for v, ip, h in top_v_q],
            'all': [_vuln_dict(v, ip, h) for v, ip, h in all_v_q],
        },
        'assets': {
            'total': total_assets,
            'online': a_stat_asset.get('online', 0),
            'offline': a_stat_asset.get('offline', 0),
            'list': [_asset_dict(a) for a in asset_list_q],
        },
        'compliance': {
            'score': global_score,
            'total_checks': total_checks,
            'compliant': compliant,
            'non_compliant': c_stat.get('non_compliant', 0),
            'total_policies': len(policies_q),
            'frameworks': frameworks,
            'by_status': c_stat,
        },
        'scans': [
            {
                'id': s.id,
                'name': s.name or f'Scan #{s.id}',
                'type': s.scanner_type,
                'status': s.status,
                'assets': s.assets_scanned or 0,
                'vulns': s.vulnerabilities_found or 0,
                'date': s.created_at.strftime('%d/%m/%Y') if s.created_at else '—',
            }
            for s in scans_q
        ],
    }


# ── Rendu final ───────────────────────────────────────────────────────────────
def _render(elements: list, title: str, date_str: str) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        topMargin=1.9 * cm, bottomMargin=1.4 * cm,
        leftMargin=MARGIN, rightMargin=MARGIN,
        title=title, author='SecureZone',
    )
    page_cb = _make_page_cb(title, date_str)
    doc.build(elements, onFirstPage=_cb_cover, onLaterPages=page_cb)
    buf.seek(0)
    return buf.read()


# ── Sections communes ─────────────────────────────────────────────────────────
def _sec_alerts_critical(d: dict, st: dict) -> list:
    elems = []
    if not d['alerts']['critical_list']:
        elems.append(Paragraph('Aucune alerte critique ou élevée active.', st['note']))
        return elems

    rows = [
        [
            Paragraph(_e(a['id']), st['cell_m']),
            Paragraph(_e(a['title']), st['cell']),
            Paragraph(_sev_xml(a['severity']), st['cell']),
            Paragraph(_e(a['category']), st['cell_m']),
            Paragraph(_e(a['source_ip']), st['cell_m']),
            Paragraph(_e(a['mitre']), st['cell_m']),
            Paragraph(_e(a['date']), st['cell_m']),
        ]
        for a in d['alerts']['critical_list']
    ]
    # 0.8 + 5.6 + 1.6 + 2.6 + 2.3 + 1.5 + 2.6 = 17 cm ✓
    cw = [0.8*cm, 5.6*cm, 1.6*cm, 2.6*cm, 2.3*cm, 1.5*cm, 2.6*cm]
    elems.append(_dtable(['#', 'Titre', 'Sév.', 'Catégorie', 'IP source', 'MITRE', 'Date'], rows, cw))
    return elems


def _sec_vuln_top(d: dict, st: dict) -> list:
    elems = []
    if not d['vulns']['top']:
        elems.append(Paragraph('Aucune vulnérabilité critique ou élevée.', st['note']))
        return elems

    rows = [
        [
            Paragraph(_e(v['cve_id']), st['cell_b']),
            Paragraph(_e(v['title']), st['cell']),
            Paragraph(_sev_xml(v['severity']), st['cell']),
            Paragraph(_e(v['cvss']), st['cell']),
            Paragraph(_e(v['asset']), st['cell_m']),
            Paragraph(_status_label(v['status']), st['cell_m']),
        ]
        for v in d['vulns']['top']
    ]
    # 2.5 + 5.2 + 1.6 + 1.0 + 4.0 + 2.7 = 17 cm ✓
    cw = [2.5*cm, 5.2*cm, 1.6*cm, 1.0*cm, 4.0*cm, 2.7*cm]
    elems.append(_dtable(['CVE', 'Titre', 'Sévérité', 'CVSS', 'Asset', 'Statut'], rows, cw))
    return elems


def _sec_compliance_summary(d: dict, st: dict) -> list:
    c = d['compliance']
    elems = []
    score_color = H_OK if c['score'] >= 80 else H_HIGH if c['score'] >= 60 else H_CRIT
    kpis = [
        (f"{c['score']}%", 'Score global', score_color),
        (c['total_policies'],  'Politiques actives', '#1E293B'),
        (c['compliant'],       'Contrôles conformes', H_OK),
        (c['non_compliant'],   'Non conformes', H_CRIT if c['non_compliant'] > 0 else H_LOW),
    ]
    elems.append(_kpi_row(kpis, st))
    elems.append(Spacer(1, 0.3 * cm))

    if c['frameworks']:
        elems.append(Paragraph('Politiques par framework', st['sub_h']))
        rows = [
            [
                Paragraph(_e(FW_LABELS.get(fw, fw)), st['cell_b']),
                Paragraph(_e(len(pols)), st['cell']),
                Paragraph(
                    f'<font color="{H_OK}">Actif</font>' if pols else '—',
                    st['cell']
                ),
            ]
            for fw, pols in c['frameworks'].items()
        ]
        # 8 + 5 + 4 = 17 cm ✓
        elems.append(_dtable(['Framework', 'Politiques', 'Statut'], rows, [8*cm, 5*cm, 4*cm]))
    return elems


def _sec_recommendations(d: dict, st: dict) -> list:
    a = d['alerts']
    v = d['vulns']
    c = d['compliance']

    recs = []
    if a['by_sev'].get('critical', 0):
        n = a['by_sev']['critical']
        recs.append(('CRITIQUE', H_CRIT, f"Investiguer et clôturer les {n} alertes critiques ouvertes", 'SOC L2/L3', '48 h'))
    if v['by_sev'].get('critical', 0):
        n = v['by_sev']['critical']
        recs.append(('CRITIQUE', H_CRIT, f"Appliquer les correctifs pour les {n} CVE critiques détectés", 'Infrastructure', '7 jours'))
    if v['by_sev'].get('high', 0):
        n = v['by_sev']['high']
        recs.append(('ÉLEVÉE', H_HIGH, f"Planifier la remédiation des {n} vulnérabilités élevées", 'Infrastructure', '30 jours'))
    if c['score'] < 80:
        recs.append(('ÉLEVÉE', H_HIGH,
                     f"Améliorer le score de conformité (actuellement {c['score']}% — objectif ≥ 80%)",
                     'Conformité', '3 mois'))
    if a['by_cat'].get('phishing', 0):
        n = a['by_cat']['phishing']
        recs.append(('MOYENNE', H_MED, f"Renforcer la sensibilisation anti-phishing ({n} détections)", 'Sécurité', '2 semaines'))
    recs.append(('MOYENNE', H_MED, 'Automatiser les scans de vulnérabilités hebdomadaires', 'SOC', 'Continu'))
    recs.append(('FAIBLE',  H_LOW, 'Maintenir les politiques de conformité à jour (ISO 27001, DORA, CIS)', 'Conformité', 'Trimestriel'))

    rows = [
        [
            Paragraph(f'<font color="{h}"><b>{p}</b></font>', st['cell']),
            Paragraph(_e(txt), st['cell']),
            Paragraph(_e(owner), st['cell_m']),
            Paragraph(_e(delay), st['cell_m']),
        ]
        for p, h, txt, owner, delay in recs
    ]
    # 2 + 9 + 3.2 + 2.8 = 17 cm ✓
    elems = [_dtable(['Priorité', 'Action recommandée', 'Responsable', 'Délai'], rows,
                     [2*cm, 9*cm, 3.2*cm, 2.8*cm])]
    return elems


# ── Rapport Exécutif ──────────────────────────────────────────────────────────
def _build_executive(d: dict, user_name: str) -> bytes:
    date_str = _fr_date(d['now'])
    st = _make_styles()
    a, v, c = d['alerts'], d['vulns'], d['compliance']
    elems = []

    # ── Couverture ──
    elems += _cover_page(
        'RAPPORT EXÉCUTIF DE SÉCURITÉ',
        'Vue d\'ensemble de la posture de sécurité',
        user_name, date_str, st,
    )

    # ── 1. Posture globale ──
    elems += _section('1. Posture de Sécurité — Synthèse', st)
    crit_a = a['by_sev'].get('critical', 0)
    crit_v = v['by_sev'].get('critical', 0)
    if crit_a > 0 or crit_v > 0:
        risk_txt = (f'<font color="{H_CRIT}"><b>RISQUE ÉLEVÉ</b></font> — '
                    f'{crit_a} alerte(s) critique(s) et {crit_v} CVE critique(s) '
                    f'nécessitent une action immédiate.')
    elif a['by_sev'].get('high', 0) > 5:
        risk_txt = (f'<font color="{H_HIGH}"><b>RISQUE MODÉRÉ</b></font> — '
                    f'La posture nécessite une attention particulière '
                    f'sur les {a["by_sev"]["high"]} alertes élevées.')
    else:
        risk_txt = (f'<font color="{H_OK}"><b>RISQUE ACCEPTABLE</b></font> — '
                    f'La posture de sécurité est globalement satisfaisante.')

    elems.append(Paragraph(risk_txt, st['body']))
    elems.append(Spacer(1, 0.3 * cm))
    kpis = [
        (a['total'],                          'Alertes totales',         '#1E293B'),
        (a['by_sev'].get('critical', 0),      'Alertes critiques',       H_CRIT),
        (a['open'],                           'Alertes ouvertes',        H_HIGH),
        (v['by_sev'].get('critical', 0),      'CVE critiques',           H_CRIT),
        (f"{c['score']}%",                    'Score conformité',
         H_OK if c['score'] >= 80 else H_HIGH),
    ]
    elems.append(_kpi_row(kpis, st))

    # ── 2. Menaces ──
    elems += _section('2. Analyse des Menaces', st)
    elems.append(Paragraph('Distribution des alertes par sévérité', st['sub_h']))
    sev_rows = []
    for sev, (_, hex_c, label) in SEV_MAP.items():
        cnt = a['by_sev'].get(sev, 0)
        if cnt == 0:
            continue
        pct = round(cnt / max(a['total'], 1) * 100, 1)
        bar = '▓' * min(int(pct / 4), 25)
        sev_rows.append([
            Paragraph(f'<font color="{hex_c}"><b>{label}</b></font>', st['cell']),
            Paragraph(_e(cnt), st['cell_b']),
            Paragraph(f'{pct}%', st['cell_m']),
            Paragraph(f'<font color="{hex_c}">{bar}</font>', st['cell']),
        ])
    if sev_rows:
        # 4 + 2 + 2 + 9 = 17 cm ✓
        elems.append(_dtable(['Sévérité', 'Alertes', '%', 'Distribution'],
                              sev_rows, [4*cm, 2*cm, 2*cm, 9*cm]))

    elems.append(Paragraph('Top catégories d\'attaque', st['sub_h']))
    cat_rows = [
        [
            Paragraph(_e(cat.replace('_', ' ').title()), st['cell']),
            Paragraph(_e(cnt), st['cell_b']),
            Paragraph(f"{round(cnt / max(a['total'], 1) * 100, 1)}%", st['cell_m']),
        ]
        for cat, cnt in sorted(a['by_cat'].items(), key=lambda x: -x[1])[:8]
    ]
    if cat_rows:
        # 9 + 4 + 4 = 17 cm ✓
        elems.append(_dtable(['Catégorie', 'Alertes', '% du total'],
                              cat_rows, [9*cm, 4*cm, 4*cm]))

    # ── 3. Alertes critiques récentes ──
    elems += _section('3. Alertes Critiques et Élevées Récentes', st)
    elems += _sec_alerts_critical(d, st)

    # ── 4. Vulnérabilités ──
    elems += _section('4. Gestion des Vulnérabilités', st)
    v_kpis = [
        (v['total'],                        'Total',             '#1E293B'),
        (v['by_sev'].get('critical', 0),    'Critiques',         H_CRIT),
        (v['by_sev'].get('high', 0),        'Élevées',           H_HIGH),
        (v['open'],                         'Ouvertes',          H_MED),
    ]
    elems.append(_kpi_row(v_kpis, st))
    elems.append(Spacer(1, 0.3 * cm))
    elems.append(Paragraph('Top CVE critiques / élevés', st['sub_h']))
    elems += _sec_vuln_top(d, st)

    # ── 5. Conformité ──
    elems += _section('5. Conformité Réglementaire', st)
    elems += _sec_compliance_summary(d, st)

    # ── 6. Scans récents ──
    if d['scans']:
        elems += _section('6. Historique des Scans Récents', st)
        scan_rows = [
            [
                Paragraph(_e(s['name']), st['cell']),
                Paragraph(_e(s['type'].upper()), st['cell_m']),
                Paragraph(_status_label(s['status']), st['cell']),
                Paragraph(_e(s['assets']), st['cell']),
                Paragraph(_e(s['vulns']), st['cell_b']),
                Paragraph(_e(s['date']), st['cell_m']),
            ]
            for s in d['scans']
        ]
        # 5.5 + 2 + 2.5 + 2 + 2 + 3 = 17 cm ✓
        elems.append(_dtable(['Scan', 'Type', 'Statut', 'Assets', 'Vulnérabilités', 'Date'],
                              scan_rows, [5.5*cm, 2*cm, 2.5*cm, 2*cm, 2*cm, 3*cm]))
        elems.append(Spacer(1, 0.3 * cm))

    # ── 7. Recommandations ──
    n_sec = '7' if d['scans'] else '6'
    elems += _section(f'{n_sec}. Recommandations Prioritaires', st)
    elems += _sec_recommendations(d, st)

    return _render(elems, 'Rapport Exécutif de Sécurité', date_str)


# ── Rapport Technique ─────────────────────────────────────────────────────────
def _build_technical(d: dict, user_name: str) -> bytes:
    date_str = _fr_date(d['now'])
    st = _make_styles()
    a, v = d['alerts'], d['vulns']
    elems = []

    elems += _cover_page(
        'RAPPORT TECHNIQUE DE SÉCURITÉ',
        'Analyse complète — Vulnérabilités · Alertes · Assets',
        user_name, date_str, st,
    )

    # ── 1. Inventaire des assets ──
    elems += _section('1. Inventaire des Actifs (Assets)', st)
    asset_kpis = [
        (d['assets']['total'],   'Total actifs',    '#1E293B'),
        (d['assets']['online'],  'En ligne',         H_OK),
        (d['assets']['offline'], 'Hors ligne',       H_MUTED),
    ]
    elems.append(_kpi_row(asset_kpis, st))
    elems.append(Spacer(1, 0.3 * cm))
    if d['assets']['list']:
        asset_rows = [
            [
                Paragraph(_e(a['ip']), st['cell_b']),
                Paragraph(_e(a['hostname']), st['cell']),
                Paragraph(_e(a['os']), st['cell_m']),
                Paragraph(_status_label(a['status']), st['cell']),
                Paragraph(_e(a['criticality']).upper(), st['cell_m']),
                Paragraph(_e(a['ports']), st['cell']),
            ]
            for a in d['assets']['list']
        ]
        # 3 + 3.5 + 4.5 + 2 + 2 + 2 = 17 cm ✓
        elems.append(_dtable(
            ['IP', 'Hostname', 'OS', 'Statut', 'Criticité', 'Ports'],
            asset_rows, [3*cm, 3.5*cm, 4.5*cm, 2*cm, 2*cm, 2*cm]
        ))

    # ── 2. Vulnérabilités complètes ──
    elems += _section('2. Analyse des Vulnérabilités', st)
    v_kpis = [
        (v['total'],                     'Total',       '#1E293B'),
        (v['by_sev'].get('critical', 0), 'Critiques',   H_CRIT),
        (v['by_sev'].get('high', 0),     'Élevées',     H_HIGH),
        (v['by_sev'].get('medium', 0),   'Moyennes',    H_MED),
        (v['open'],                      'Ouvertes',    H_HIGH),
    ]
    elems.append(_kpi_row(v_kpis, st))
    elems.append(Spacer(1, 0.3 * cm))

    if v['all']:
        elems.append(Paragraph(f'Toutes les vulnérabilités ({len(v["all"])} affichées)', st['sub_h']))
        vuln_rows = [
            [
                Paragraph(_e(vn['cve_id']), st['cell_b']),
                Paragraph(_e(vn['title']), st['cell']),
                Paragraph(_sev_xml(vn['severity']), st['cell']),
                Paragraph(_e(vn['cvss']), st['cell']),
                Paragraph(_e(vn['asset']), st['cell_m']),
                Paragraph(_e(vn['service']), st['cell_m']),
                Paragraph(_status_label(vn['status']), st['cell_m']),
            ]
            for vn in v['all']
        ]
        # 2.3 + 4.5 + 1.5 + 1 + 3.2 + 2 + 2.5 = 17 cm ✓
        elems.append(_dtable(
            ['CVE', 'Titre', 'Sév.', 'CVSS', 'Asset', 'Service', 'Statut'],
            vuln_rows, [2.3*cm, 4.5*cm, 1.5*cm, 1*cm, 3.2*cm, 2*cm, 2.5*cm]
        ))

        if v['all'] and v['all'][0].get('solution'):
            elems.append(Spacer(1, 0.4 * cm))
            elems.append(Paragraph('Plan de remédiation (top vulnérabilités)', st['sub_h']))
            rem_rows = [
                [
                    Paragraph(_e(vn['cve_id']), st['cell_b']),
                    Paragraph(_sev_xml(vn['severity']), st['cell']),
                    Paragraph(_e(vn['asset']), st['cell_m']),
                    Paragraph(_e(vn['solution'] or 'Voir avis de sécurité éditeur'), st['cell']),
                ]
                for vn in v['all'][:15] if vn.get('solution')
            ]
            if rem_rows:
                # 2.5 + 1.5 + 3 + 10 = 17 cm ✓
                elems.append(_dtable(
                    ['CVE', 'Sév.', 'Asset', 'Solution recommandée'],
                    rem_rows, [2.5*cm, 1.5*cm, 3*cm, 10*cm]
                ))

    # ── 3. Alertes SIEM complètes ──
    elems += _section('3. Alertes SIEM — Détail Complet', st)
    elems.append(Paragraph('Alertes critiques et élevées récentes', st['sub_h']))
    elems += _sec_alerts_critical(d, st)

    if a['all']:
        elems.append(Spacer(1, 0.4 * cm))
        elems.append(Paragraph(f'Toutes les alertes récentes ({len(a["all"])} affichées)', st['sub_h']))
        all_a_rows = [
            [
                Paragraph(_e(al['id']), st['cell_m']),
                Paragraph(_e(al['title']), st['cell']),
                Paragraph(_sev_xml(al['severity']), st['cell']),
                Paragraph(_e(al['category']), st['cell_m']),
                Paragraph(_status_label(al['status']), st['cell_m']),
                Paragraph(_e(al['source_ip']), st['cell_m']),
                Paragraph(_e(al['date']), st['cell_m']),
            ]
            for al in a['all']
        ]
        # 0.7 + 5 + 1.5 + 2.5 + 2 + 2.3 + 3 = 17 cm ✓
        elems.append(_dtable(
            ['#', 'Titre', 'Sév.', 'Catégorie', 'Statut', 'IP source', 'Date'],
            all_a_rows, [0.7*cm, 5*cm, 1.5*cm, 2.5*cm, 2*cm, 2.3*cm, 3*cm]
        ))

    # ── 4. Scans ──
    if d['scans']:
        elems += _section('4. Historique des Scans', st)
        scan_rows = [
            [
                Paragraph(_e(s['name']), st['cell']),
                Paragraph(_e(s['type'].upper()), st['cell_m']),
                Paragraph(_status_label(s['status']), st['cell']),
                Paragraph(_e(s['assets']), st['cell']),
                Paragraph(_e(s['vulns']), st['cell_b']),
                Paragraph(_e(s['date']), st['cell_m']),
            ]
            for s in d['scans']
        ]
        elems.append(_dtable(
            ['Scan', 'Type', 'Statut', 'Assets', 'Vulnérabilités', 'Date'],
            scan_rows, [5.5*cm, 2*cm, 2.5*cm, 2*cm, 2*cm, 3*cm]
        ))

    # ── 5. Recommandations ──
    elems += _section('5. Recommandations Techniques', st)
    elems += _sec_recommendations(d, st)

    return _render(elems, 'Rapport Technique de Sécurité', date_str)


# ── Rapport de Conformité ─────────────────────────────────────────────────────
def _build_compliance(d: dict, user_name: str) -> bytes:
    date_str = _fr_date(d['now'])
    st = _make_styles()
    c = d['compliance']
    elems = []

    elems += _cover_page(
        'RAPPORT DE CONFORMITÉ',
        'ISO 27001 · DORA · CIS Controls — Évaluation continue',
        user_name, date_str, st,
    )

    # ── 1. Score global ──
    elems += _section('1. Score Global de Conformité', st)
    elems += _sec_compliance_summary(d, st)

    score = c['score']
    if score >= 90:
        commentary = (f'<font color="{H_OK}"><b>EXCELLENT</b></font> — '
                      f'Le niveau de conformité est très satisfaisant ({score}%). '
                      f'Maintenir la surveillance continue et mettre à jour les politiques trimestriellement.')
    elif score >= 70:
        commentary = (f'<font color="{H_MED}"><b>SATISFAISANT</b></font> — '
                      f'Le score de conformité ({score}%) est acceptable mais des axes d\'amélioration existent. '
                      f'Prioriser les contrôles non conformes de sévérité haute.')
    else:
        commentary = (f'<font color="{H_CRIT}"><b>INSUFFISANT</b></font> — '
                      f'Le score de conformité ({score}%) est en dessous des seuils requis. '
                      f'Un plan d\'action correctif immédiat est nécessaire.')
    elems.append(Spacer(1, 0.3 * cm))
    elems.append(Paragraph(commentary, st['body']))

    # ── 2. Politiques par framework ──
    sec_num = 2
    for fw, policies in c['frameworks'].items():
        fw_label = FW_LABELS.get(fw, fw)
        elems += _section(f'{sec_num}. {fw_label}', st)
        elems.append(Paragraph(
            f'{len(policies)} politiques actives dans le framework {fw_label}.', st['body']
        ))

        rows = [
            [
                Paragraph(_e(p['control_id']), st['cell_m']),
                Paragraph(_e(p['name']), st['cell']),
                Paragraph(_sev_xml(p['severity']), st['cell']),
                Paragraph(_e(p['rule_type'].replace('_', ' ').title()), st['cell_m']),
            ]
            for p in policies
        ]
        # 2.5 + 8.5 + 2 + 4 = 17 cm ✓
        elems.append(_dtable(
            ['Contrôle', 'Politique', 'Sévérité', 'Type de règle'],
            rows, [2.5*cm, 8.5*cm, 2*cm, 4*cm]
        ))
        sec_num += 1

    # ── N. Statut des vérifications ──
    if c['by_status']:
        elems += _section(f'{sec_num}. Statut des Vérifications de Conformité', st)
        check_rows = [
            [
                Paragraph(_status_label(status), st['cell_b']),
                Paragraph(_e(count), st['cell']),
                Paragraph(
                    f"{round(count / max(c['total_checks'], 1) * 100, 1)}%",
                    st['cell_m']
                ),
            ]
            for status, count in sorted(c['by_status'].items(), key=lambda x: -x[1])
        ]
        # 8 + 5 + 4 = 17 cm ✓
        elems.append(_dtable(
            ['Statut', 'Nombre de vérifications', '% du total'],
            check_rows, [8*cm, 5*cm, 4*cm]
        ))
        sec_num += 1

    # ── N. Plan d'action ──
    elems += _section(f'{sec_num}. Plan d\'Action Correctif', st)
    action_rows = []
    if c['non_compliant'] > 0:
        action_rows.append([
            Paragraph('<font color="#DC2626"><b>CRITIQUE</b></font>', st['cell']),
            Paragraph(f"Corriger les {c['non_compliant']} contrôles non conformes identifiés", st['cell']),
            Paragraph('Équipe Conformité', st['cell_m']),
            Paragraph('Immédiat', st['cell_m']),
        ])
    if score < 80:
        action_rows.append([
            Paragraph('<font color="#EA580C"><b>ÉLEVÉE</b></font>', st['cell']),
            Paragraph(f"Définir un plan de mise en conformité pour atteindre ≥ 80% (actuel : {score}%)", st['cell']),
            Paragraph('RSSI / Direction', st['cell_m']),
            Paragraph('3 mois', st['cell_m']),
        ])
    action_rows += [
        [
            Paragraph('<font color="#D97706"><b>MOYENNE</b></font>', st['cell']),
            Paragraph('Organiser une revue trimestrielle des politiques de sécurité', st['cell']),
            Paragraph('Équipe Sécurité', st['cell_m']),
            Paragraph('Trimestriel', st['cell_m']),
        ],
        [
            Paragraph('<font color="#16A34A"><b>FAIBLE</b></font>', st['cell']),
            Paragraph('Documenter les exceptions accordées avec justification et durée', st['cell']),
            Paragraph('Conformité', st['cell_m']),
            Paragraph('Continu', st['cell_m']),
        ],
    ]
    # 2 + 9 + 3.2 + 2.8 = 17 cm ✓
    elems.append(_dtable(
        ['Priorité', 'Action', 'Responsable', 'Délai'],
        action_rows, [2*cm, 9*cm, 3.2*cm, 2.8*cm]
    ))

    return _render(elems, 'Rapport de Conformité Réglementaire', date_str)


# ── Endpoints ─────────────────────────────────────────────────────────────────
def _pdf_response(pdf_bytes: bytes, filename: str) -> StreamingResponse:
    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type='application/pdf',
        headers={'Content-Disposition': f'attachment; filename="{filename}"'},
    )


@router.get('/executive', summary='Rapport exécutif PDF (management / CISO)')
async def report_executive(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    data = await _collect(db)
    user_name = getattr(current_user, 'full_name', None) or getattr(current_user, 'email', 'Analyste')
    pdf = _build_executive(data, user_name)
    date_tag = data['now'].strftime('%Y%m%d')
    return _pdf_response(pdf, f'securezone-executif-{date_tag}.pdf')


@router.get('/technical', summary='Rapport technique complet (SOC engineers)')
async def report_technical(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    data = await _collect(db)
    user_name = getattr(current_user, 'full_name', None) or getattr(current_user, 'email', 'Analyste')
    pdf = _build_technical(data, user_name)
    date_tag = data['now'].strftime('%Y%m%d')
    return _pdf_response(pdf, f'securezone-technique-{date_tag}.pdf')


@router.get('/compliance', summary='Rapport de conformité (ISO 27001 / DORA / CIS)')
async def report_compliance(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    data = await _collect(db)
    user_name = getattr(current_user, 'full_name', None) or getattr(current_user, 'email', 'Analyste')
    pdf = _build_compliance(data, user_name)
    date_tag = data['now'].strftime('%Y%m%d')
    return _pdf_response(pdf, f'securezone-conformite-{date_tag}.pdf')
