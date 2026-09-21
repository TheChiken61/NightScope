#!/usr/bin/env python3
"""
recon_report.py — Reconocimiento y escaneo de vulnerabilidades no intrusivo,
con generación automática de informe en Excel.

Uso:
    python3 recon_report.py <dominio_o_url> [opciones]

Ejemplo:
    python3 recon_report.py https://ejemplo.gov.co --output informe_ejemplo.xlsx

Herramientas orquestadas (deben estar instaladas): whois, dig, nmap, sslscan,
wafw00f, whatweb, nikto, nuclei.

IMPORTANTE: esta herramienta solo realiza reconocimiento y detección de
vulnerabilidades (sin explotación). El uso contra objetivos sin autorización
explícita es responsabilidad exclusiva de quien la ejecuta.
"""

import argparse
import datetime
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from urllib.parse import urlparse

import requests
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter
from openpyxl.cell.cell import ILLEGAL_CHARACTERS_RE

DEFAULT_NUCLEI_TAGS = "exposure,misconfig,tech,ssl,headers"
DEFAULT_DIRSEARCH_EXTENSIONS = "php,html,js,txt,bak,zip,sql,json,config"
DEFAULT_DIRSEARCH_EXCLUDE_STATUS = "302,404"
REQUIRED_TOOLS = ["whois", "dig", "nmap", "sslscan", "wafw00f", "whatweb", "nikto", "nuclei", "dirsearch"]

ANSI_RE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")


def sanitize(text):
    """Strip ANSI color codes and characters illegal in XLSX cells."""
    if text is None:
        return ""
    text = ANSI_RE.sub("", str(text))
    text = ILLEGAL_CHARACTERS_RE.sub("", text)
    return text


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def check_tools():
    missing = [t for t in REQUIRED_TOOLS if shutil.which(t) is None]
    if missing:
        print(f"[!] Faltan herramientas en el PATH: {', '.join(missing)}")
        print("    Instálalas antes de continuar (todas disponibles en repos de Kali Linux).")
        sys.exit(1)


def run(cmd, timeout=120):
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return sanitize(proc.stdout.strip() or proc.stderr.strip())
    except subprocess.TimeoutExpired:
        return f"[timeout tras {timeout}s ejecutando: {' '.join(cmd)}]"
    except Exception as e:
        return f"[error ejecutando {' '.join(cmd)}: {e}]"


def confirm_authorization(target, assume_yes):
    if assume_yes:
        return
    print(f"\nEstás a punto de ejecutar reconocimiento y escaneo de vulnerabilidades contra:\n  {target}\n")
    print("Confirma que tienes autorización explícita para realizar estas pruebas sobre este objetivo.")
    resp = input("¿Confirmas que tienes autorización? [escribe 'si' para continuar]: ").strip().lower()
    if resp not in ("si", "sí", "yes", "y"):
        print("Cancelado. No se ejecutó ninguna prueba.")
        sys.exit(0)


# ------------------------------------------------------------------
# Recon steps
# ------------------------------------------------------------------

def do_whois(domain):
    return run(["whois", domain], timeout=30)


def do_dns(domain):
    records = {}
    for rtype in ["A", "AAAA", "NS", "MX", "TXT", "SOA", "CNAME"]:
        out = run(["dig", "+short", domain, rtype], timeout=20)
        records[rtype] = out or "(sin registros)"
    return records


def do_http_headers(url):
    try:
        r = requests.get(url, timeout=15, allow_redirects=False, verify=True)
        headers_text = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        return sanitize(f"HTTP/{r.raw.version} {r.status_code} {r.reason}\n{headers_text}")
    except Exception as e:
        return f"[error obteniendo headers: {e}]"


def do_nmap(host):
    return run(["nmap", "-Pn", "-sV", "--top-ports", "1000", "-T3", host], timeout=180)


def do_sslscan(host):
    return run(["sslscan", "--no-colour", host], timeout=60)


def do_wafw00f(url):
    return run(["wafw00f", url], timeout=60)


def do_whatweb(url):
    return run(["whatweb", "-a", "3", url], timeout=60)


def do_nikto(url, maxtime):
    return run(["nikto", "-h", url, "-Tuning", "x6", "-maxtime", f"{maxtime}s"], timeout=maxtime + 30)


def do_nuclei(url, tags, rate_limit, timeout):
    out = run(
        ["nuclei", "-u", url, "-tags", tags, "-rl", str(rate_limit), "-timeout", "10", "-jsonl", "-silent"],
        timeout=timeout,
    )
    if out.startswith("[timeout"):
        print(f"    [!] nuclei no terminó dentro de {timeout}s — sube --nuclei-timeout si esto se repite.")
        return []
    findings = []
    for line in out.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            findings.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return findings


def do_dirsearch(url, extensions, exclude_status, max_time, max_rate):
    """Descubrimiento de contenido. Excluye por defecto 302/404 para filtrar
    respuestas 'soft-404' que muchos frameworks devuelven para cualquier ruta
    inexistente (evita miles de falsos positivos)."""
    fd, tmp_json = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    cmd = [
        "dirsearch", "-u", url, "-e", extensions, "-x", exclude_status,
        "--max-time", str(max_time), "--max-rate", str(max_rate),
        "-o", tmp_json, "--format=json", "-q", "--no-color",
    ]
    run(cmd, timeout=max_time + 60)
    results = []
    try:
        with open(tmp_json) as f:
            data = json.load(f)
        results = data.get("results", [])
    except Exception:
        results = []
    finally:
        try:
            os.remove(tmp_json)
        except OSError:
            pass
    return results


# ------------------------------------------------------------------
# Excel report
# ------------------------------------------------------------------

SEV_FILL = {
    "critical": PatternFill("solid", fgColor="F8696B"),
    "high": PatternFill("solid", fgColor="FFB3B3"),
    "medium": PatternFill("solid", fgColor="FCE4D6"),
    "low": PatternFill("solid", fgColor="FFF2CC"),
    "info": PatternFill("solid", fgColor="DDEBF7"),
    "unknown": PatternFill("solid", fgColor="E7E6E6"),
}
SEV_ORDER = ["critical", "high", "medium", "low", "info", "unknown"]


def build_report(output_path, target, domain, host_ip, dns_records, whois_out, headers_out,
                  nmap_out, sslscan_out, wafw00f_out, whatweb_out, nikto_out, nuclei_findings,
                  nuclei_tags, dirsearch_results):
    wb = Workbook()

    header_font = Font(bold=True, color="FFFFFF")
    header_fill = PatternFill("solid", fgColor="1F4E78")
    wrap = Alignment(wrap_text=True, vertical="top", horizontal="left")
    center = Alignment(wrap_text=True, vertical="center", horizontal="center")
    thin = Side(style="thin", color="B7B7B7")
    border = Border(left=thin, right=thin, top=thin, bottom=thin)

    # ---------------- Resumen ----------------
    ws = wb.active
    ws.title = "Resumen"
    ws.sheet_view.showGridLines = False
    ws.column_dimensions["A"].width = 24
    ws.column_dimensions["B"].width = 80

    ws["A1"] = "Informe de Reconocimiento y Vulnerabilidades"
    ws["A1"].font = Font(size=16, bold=True)
    ws.merge_cells("A1:B1")
    ws["A2"] = target
    ws["A2"].font = Font(size=11, italic=True, color="555555")
    ws.merge_cells("A2:B2")

    sev_counts = {s: 0 for s in SEV_ORDER}
    for f in nuclei_findings:
        sev = (f.get("info", {}).get("severity") or "unknown").lower()
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    rows = [
        ("Fecha de generación", datetime.datetime.now().strftime("%Y-%m-%d %H:%M")),
        ("Objetivo", target),
        ("Dominio", domain),
        ("IP resuelta", host_ip or "(no resuelta)"),
        ("Plantillas nuclei usadas", nuclei_tags),
        ("Total hallazgos nuclei", str(len(nuclei_findings))),
        ("Rutas encontradas (dirsearch)", str(len(dirsearch_results))),
    ]
    r = 4
    for label, value in rows:
        ws.cell(row=r, column=1, value=label).font = Font(bold=True)
        ws.cell(row=r, column=1).border = border
        ws.cell(row=r, column=2, value=value).alignment = wrap
        ws.cell(row=r, column=2).border = border
        r += 1

    r += 1
    ws.cell(row=r, column=1, value="Severidad (nuclei)").font = Font(bold=True)
    r += 1
    ws.cell(row=r, column=1, value="Severidad").font = header_font
    ws.cell(row=r, column=1).fill = header_fill
    ws.cell(row=r, column=2, value="Cantidad").font = header_font
    ws.cell(row=r, column=2).fill = header_fill
    r += 1
    for sev in SEV_ORDER:
        if sev_counts.get(sev, 0) == 0 and sev == "unknown":
            continue
        ws.cell(row=r, column=1, value=sev.capitalize()).fill = SEV_FILL[sev]
        ws.cell(row=r, column=1).border = border
        ws.cell(row=r, column=2, value=sev_counts.get(sev, 0)).alignment = center
        ws.cell(row=r, column=2).border = border
        r += 1

    r += 2
    note = ("Informe generado automáticamente. Incluye reconocimiento, descubrimiento de "
            "contenido (dirsearch) y detección de vulnerabilidades no intrusiva (nuclei "
            "restringido a plantillas de exposición, misconfiguración, tecnologías, SSL y "
            "headers). No incluye pruebas de explotación activa ni fuerza bruta de credenciales.")
    ws.cell(row=r, column=1, value=note).alignment = wrap
    ws.merge_cells(start_row=r, start_column=1, end_row=r, end_column=2)
    ws.row_dimensions[r].height = 60

    # ---------------- Hallazgos (nuclei) ----------------
    ws2 = wb.create_sheet("Hallazgos-Nuclei")
    ws2.sheet_view.showGridLines = False
    headers_row = ["Template", "Nombre", "Severidad", "Tipo", "Matched-At", "Descripción"]
    widths = [28, 32, 12, 10, 45, 45]
    for i, (h, w) in enumerate(zip(headers_row, widths), start=1):
        c = ws2.cell(row=1, column=i, value=h)
        c.font = header_font
        c.fill = header_fill
        c.alignment = center
        c.border = border
        ws2.column_dimensions[get_column_letter(i)].width = w
    ws2.freeze_panes = "A2"

    r = 2
    for f in sorted(nuclei_findings, key=lambda x: SEV_ORDER.index((x.get("info", {}).get("severity") or "unknown").lower())
                     if (x.get("info", {}).get("severity") or "unknown").lower() in SEV_ORDER else 99):
        info = f.get("info", {})
        sev = (info.get("severity") or "unknown").lower()
        ws2.cell(row=r, column=1, value=sanitize(f.get("template-id", ""))).alignment = wrap
        ws2.cell(row=r, column=2, value=sanitize(info.get("name", ""))).alignment = wrap
        sc = ws2.cell(row=r, column=3, value=sev.capitalize())
        sc.alignment = center
        sc.fill = SEV_FILL.get(sev, SEV_FILL["unknown"])
        ws2.cell(row=r, column=4, value=sanitize(f.get("type", ""))).alignment = center
        ws2.cell(row=r, column=5, value=sanitize(f.get("matched-at", ""))).alignment = wrap
        ws2.cell(row=r, column=6, value=sanitize(info.get("description", ""))).alignment = wrap
        for col in range(1, 7):
            ws2.cell(row=r, column=col).border = border
        ws2.row_dimensions[r].height = 45
        r += 1

    # ---------------- Nikto (raw) ----------------
    ws3 = wb.create_sheet("Nikto-Raw")
    ws3.column_dimensions["A"].width = 140
    ws3.cell(row=1, column=1, value="Salida cruda de Nikto").font = Font(bold=True)
    r = 3
    for line in nikto_out.splitlines():
        ws3.cell(row=r, column=1, value=line)
        r += 1

    # ---------------- Dirsearch ----------------
    ws5 = wb.create_sheet("Dirsearch")
    ws5.sheet_view.showGridLines = False
    ds_headers = ["Status", "URL", "Content-Length", "Content-Type", "Redirect"]
    ds_widths = [10, 65, 14, 22, 45]
    for i, (h, w) in enumerate(zip(ds_headers, ds_widths), start=1):
        c = ws5.cell(row=1, column=i, value=h)
        c.font = header_font
        c.fill = header_fill
        c.alignment = center
        c.border = border
        ws5.column_dimensions[get_column_letter(i)].width = w
    ws5.freeze_panes = "A2"

    STATUS_FILL = {
        "2": PatternFill("solid", fgColor="C6E0B4"),
        "3": PatternFill("solid", fgColor="FFF2CC"),
        "4": PatternFill("solid", fgColor="FCE4D6"),
        "5": PatternFill("solid", fgColor="FFB3B3"),
    }
    r = 2
    for entry in sorted(dirsearch_results, key=lambda e: e.get("url", "")):
        status = str(entry.get("status", ""))
        sc = ws5.cell(row=r, column=1, value=status)
        sc.alignment = center
        sc.fill = STATUS_FILL.get(status[:1], PatternFill("solid", fgColor="E7E6E6"))
        ws5.cell(row=r, column=2, value=sanitize(entry.get("url", ""))).alignment = wrap
        ws5.cell(row=r, column=3, value=entry.get("content-length", "")).alignment = center
        ws5.cell(row=r, column=4, value=sanitize(entry.get("content-type", ""))).alignment = wrap
        ws5.cell(row=r, column=5, value=sanitize(entry.get("redirect", ""))).alignment = wrap
        for col in range(1, 6):
            ws5.cell(row=r, column=col).border = border
        r += 1
    if not dirsearch_results:
        ws5.cell(row=2, column=1, value="Sin resultados (o dirsearch fue omitido con --skip-dirsearch).")

    # ---------------- Recon crudo ----------------
    ws4 = wb.create_sheet("Recon-Raw")
    ws4.column_dimensions["A"].width = 22
    ws4.column_dimensions["B"].width = 130
    blocks = [
        ("WHOIS", whois_out),
        ("DNS", "\n".join(f"{k}: {v}" for k, v in dns_records.items())),
        ("HTTP Headers", headers_out),
        ("nmap", nmap_out),
        ("sslscan", sslscan_out),
        ("wafw00f", wafw00f_out),
        ("whatweb", whatweb_out),
    ]
    r = 1
    for label, content in blocks:
        ws4.cell(row=r, column=1, value=label).font = Font(bold=True)
        ws4.cell(row=r, column=1).alignment = Alignment(vertical="top")
        ws4.cell(row=r, column=2, value=content).alignment = wrap
        ws4.row_dimensions[r].height = min(400, 15 * (content.count("\n") + 2))
        r += 1

    wb.save(output_path)


# ------------------------------------------------------------------
# Main
# ------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Reconocimiento y vulnerabilidades -> informe Excel")
    parser.add_argument("target", nargs="?",
                         help="Dominio o URL objetivo (ej: https://ejemplo.gov.co). Si se omite, se pregunta interactivamente.")
    parser.add_argument("--output", "-o", help="Ruta del archivo Excel de salida")
    parser.add_argument("--nuclei-tags", default=DEFAULT_NUCLEI_TAGS,
                         help=f"Tags de nuclei a usar (default: {DEFAULT_NUCLEI_TAGS} — no incluye CVEs/exploits)")
    parser.add_argument("--nikto-maxtime", type=int, default=90, help="Tiempo máximo de nikto en segundos")
    parser.add_argument("--nuclei-rate-limit", type=int, default=10, help="Requests/seg para nuclei")
    parser.add_argument("--nuclei-timeout", type=int, default=420, help="Timeout total de nuclei en segundos")
    parser.add_argument("--skip-dirsearch", action="store_true", help="Omitir el descubrimiento de contenido con dirsearch")
    parser.add_argument("--dirsearch-extensions", default=DEFAULT_DIRSEARCH_EXTENSIONS,
                         help=f"Extensiones para dirsearch (default: {DEFAULT_DIRSEARCH_EXTENSIONS})")
    parser.add_argument("--dirsearch-exclude-status", default=DEFAULT_DIRSEARCH_EXCLUDE_STATUS,
                         help=f"Códigos de estado a excluir en dirsearch (default: {DEFAULT_DIRSEARCH_EXCLUDE_STATUS})")
    parser.add_argument("--dirsearch-maxtime", type=int, default=120, help="Tiempo máximo de dirsearch en segundos")
    parser.add_argument("--dirsearch-rate", type=int, default=20, help="Requests/seg máximos para dirsearch")
    parser.add_argument("--yes", action="store_true",
                         help="Omitir la confirmación interactiva de autorización (úsalo solo en pipelines ya autorizados)")
    args = parser.parse_args()

    check_tools()

    raw_target = args.target or input("URL o dominio objetivo (ej: https://ejemplo.gov.co): ").strip()
    if not raw_target:
        print("No se indicó objetivo. Saliendo.")
        sys.exit(1)
    target = raw_target if raw_target.startswith("http") else f"https://{raw_target}"
    domain = urlparse(target).hostname

    confirm_authorization(target, args.yes)

    print(f"[*] Objetivo: {target}")

    print("[*] WHOIS...")
    whois_out = do_whois(domain)

    print("[*] DNS...")
    dns_records = do_dns(domain)
    host_ip = dns_records.get("A", "").splitlines()[0] if dns_records.get("A") not in (None, "(sin registros)") else None

    print("[*] HTTP headers...")
    headers_out = do_http_headers(target)

    print("[*] nmap (puede tardar)...")
    nmap_out = do_nmap(domain)

    print("[*] sslscan...")
    sslscan_out = do_sslscan(domain)

    print("[*] wafw00f...")
    wafw00f_out = do_wafw00f(target)

    print("[*] whatweb...")
    whatweb_out = do_whatweb(target)

    print("[*] nikto (no intrusivo, con límite de tiempo)...")
    nikto_out = do_nikto(target, args.nikto_maxtime)

    print(f"[*] nuclei (tags: {args.nuclei_tags}, sin plantillas de explotación/CVE)...")
    nuclei_findings = do_nuclei(target, args.nuclei_tags, args.nuclei_rate_limit, args.nuclei_timeout)

    dirsearch_results = []
    if not args.skip_dirsearch:
        print(f"[*] dirsearch (descubrimiento de contenido, max {args.dirsearch_maxtime}s)...")
        dirsearch_results = do_dirsearch(
            target, args.dirsearch_extensions, args.dirsearch_exclude_status,
            args.dirsearch_maxtime, args.dirsearch_rate,
        )
    else:
        print("[*] dirsearch omitido (--skip-dirsearch)")

    output_path = args.output or f"informe_{domain}.xlsx"
    print(f"[*] Generando Excel: {output_path}")
    build_report(
        output_path, target, domain, host_ip, dns_records, whois_out, headers_out,
        nmap_out, sslscan_out, wafw00f_out, whatweb_out, nikto_out, nuclei_findings,
        args.nuclei_tags, dirsearch_results,
    )
    print(f"[+] Listo: {output_path}")


if __name__ == "__main__":
    main()
