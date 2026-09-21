# recon-report-tool

Herramienta de línea de comandos que automatiza una fase de **reconocimiento,
descubrimiento de contenido y detección de vulnerabilidades no intrusiva**
contra cualquier dominio/URL que le indiques, y genera un informe en Excel
(`.xlsx`) con todos los hallazgos.

> ⚠️ Uso exclusivo en objetivos donde tengas **autorización explícita** para
> realizar pruebas de seguridad (pentesting autorizado, bug bounty en
> alcance, o infraestructura propia). El script pide confirmación antes de
> ejecutar nada, salvo que se use `--yes`.

## Qué hace

Orquesta, en este orden, contra la URL que le pases:

1. `whois` — información de registro del dominio
2. `dig` — registros DNS (A, AAAA, NS, MX, TXT, SOA, CNAME)
3. HTTP headers (vía `requests`, sin seguir redirects)
4. `nmap -sV --top-ports 1000` — puertos abiertos y versión de servicios
5. `sslscan` — configuración TLS/cifrados
6. `wafw00f` — detección de WAF
7. `whatweb` — fingerprinting de tecnologías
8. `nikto` — escaneo de vulnerabilidades web (con límite de tiempo)
9. `nuclei` — **solo** plantillas de detección no intrusivas por defecto:
   `exposure,misconfig,tech,ssl,headers` (sin plantillas de CVE/explotación
   activa; se puede cambiar con `--nuclei-tags`, bajo tu propio criterio)
10. `dirsearch` — descubrimiento de contenido/rutas (con límite de tiempo y
    tasa; excluye por defecto respuestas 302/404 para filtrar los falsos
    positivos "soft-404" que muchos sitios devuelven para cualquier ruta)

Todo se consolida en un `.xlsx` con hojas: **Resumen** (conteo por severidad
y por hallazgos), **Hallazgos-Nuclei** (tabla estructurada con severidad),
**Nikto-Raw**, **Dirsearch** (rutas encontradas con su status/tamaño) y
**Recon-Raw** (WHOIS/DNS/headers/nmap/sslscan/wafw00f/whatweb).

## Requisitos

Herramientas del sistema (Kali Linux las trae, o instálalas vía `apt`):

```
whois dig nmap sslscan wafw00f whatweb nikto nuclei dirsearch
```

Dependencias Python:

```bash
pip install -r requirements.txt
```

## Uso

Modo directo (pasas la URL como argumento):

```bash
python3 recon_report.py https://ejemplo.gov.co
python3 recon_report.py ejemplo.gov.co --output informe_ejemplo.xlsx
```

Modo interactivo (si no pasas nada, te la pregunta):

```bash
python3 recon_report.py
URL o dominio objetivo (ej: https://ejemplo.gov.co): ejemplo.gov.co
```

En ambos casos, antes de ejecutar nada te pide confirmar que tienes
autorización sobre el objetivo (salvo que uses `--yes`).

Opciones:

| Flag | Descripción | Default |
|---|---|---|
| `--output`, `-o` | Ruta del Excel de salida | `informe_<dominio>.xlsx` |
| `--nuclei-tags` | Tags de plantillas nuclei | `exposure,misconfig,tech,ssl,headers` |
| `--nuclei-rate-limit` | Requests/segundo para nuclei | `10` |
| `--nuclei-timeout` | Timeout total de nuclei (segundos) | `420` |
| `--nikto-maxtime` | Tiempo máximo de nikto (segundos) | `90` |
| `--skip-dirsearch` | Omite el descubrimiento de contenido | (se ejecuta) |
| `--dirsearch-extensions` | Extensiones a probar | `php,html,js,txt,bak,zip,sql,json,config` |
| `--dirsearch-exclude-status` | Códigos de estado a excluir | `302,404` |
| `--dirsearch-maxtime` | Tiempo máximo de dirsearch (segundos) | `120` |
| `--dirsearch-rate` | Requests/segundo máximos para dirsearch | `20` |
| `--yes` | Omite la confirmación interactiva de autorización | (pide confirmación) |

## Limitaciones / alcance deliberado

- No hace fuerza bruta de credenciales ni envía payloads de explotación
  activa (SQLi, XSS, RCE, etc.). Es intencional: esta herramienta cubre
  reconocimiento, descubrimiento de contenido y detección — no explotación.
- `nikto` y `dirsearch` corren con límite de tiempo y tasa para no generar
  carga excesiva sobre el objetivo; ajusta `--dirsearch-rate` y
  `--nuclei-rate-limit` a la baja si el objetivo es sensible.
- `dirsearch` excluye 302/404 por defecto porque muchos sitios (como el que
  originó este script) devuelven 302 hacia una página de error genérica para
  *cualquier* ruta inexistente — sin ese filtro, el reporte se llena de
  miles de falsos positivos. Si tu objetivo no tiene ese comportamiento,
  ajusta `--dirsearch-exclude-status`.
- Los resultados de nuclei dependen de las plantillas instaladas/actualizadas
  (`nuclei -update-templates`).

## Origen

Este script nace de un flujo de trabajo manual (whois → dig → headers →
nmap → sslscan/wafw00f/whatweb → nikto → nuclei → dirsearch) usado en una
auditoría real, que se automatizó para reutilizarlo en futuros objetivos
autorizados con solo indicar la URL.
