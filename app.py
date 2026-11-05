import io
import os
import pandas as pd
import plotly.express as px
import streamlit as st
from google import genai
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

# ==========================================================
# CONFIGURACIÓN Y ESTILO VISUAL MODERNO (SOC WORKBENCH)
# ==========================================================
st.set_page_config(
    page_title="SOC L2 Incident AI Workbench",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Inyección de estilos CSS para una interfaz moderna, limpia y profesional
st.markdown(
    """
<style>
    /* Estilos generales y tipografía */
    .main-title {
        font-size: 2.2rem;
        font-weight: 700;
        color: #1E3A8A;
        margin-bottom: 0.2rem;
    }
    .sub-title {
        font-size: 1.05rem;
        color: #4B5563;
        margin-bottom: 1.5rem;
    }
    /* Tarjetas de Métricas */
    div[data-testid="stMetricValue"] {
        font-size: 1.8rem;
        font-weight: 700;
        color: #1F2937;
    }
    /* Estilo de Contenedores de Incidentes */
    .incident-card {
        padding: 1.2rem;
        border-radius: 10px;
        border: 2px solid #E5E7EB;
        background-color: #F9FAFB;
        margin-bottom: 1rem;
    }
    .badge-critical {
        background-color: #FEE2E2;
        color: #991B1B;
        padding: 4px 8px;
        border-radius: 6px;
        font-weight: 600;
        font-size: 0.85rem;
    }
    .badge-high {
        background-color: #FFEDD5;
        color: #9A3412;
        padding: 4px 8px;
        border-radius: 6px;
        font-weight: 600;
        font-size: 0.85rem;
    }
    .badge-medium {
        background-color: #FEF3C7;
        color: #92400E;
        padding: 4px 8px;
        border-radius: 6px;
        font-weight: 600;
        font-size: 0.85rem;
    }
</style>
""",
    unsafe_allow_html=True,
)

st.markdown(
    "<div class='main-title'>🛡️ SOC Nivel 2 - Threat Response & Incident"
    " Workbench</div>",
    unsafe_allow_html=True,
)
st.markdown(
    "<div class='sub-title'>Plataforma analítica integrada: Ingesta de"
    " telemetría, reconstrucción de Kill Chain, correlación contextual y"
    " documentación ejecutiva con IA.</div>",
    unsafe_allow_html=True,
)

# Inicialización de la API de IA (Secrets de Streamlit o variables de entorno)
api_key = st.secrets.get("GEMINI_API_KEY", os.environ.get("GEMINI_API_KEY", ""))
client = None
if api_key:
  try:
    client = genai.Client(api_key=api_key)
  except Exception as e:
    st.sidebar.warning(f"Error cliente IA: {e}")

# Sidebar de Control y Estado
with st.sidebar:
  st.header("⚙️ Estado de la Plataforma")
  if api_key:
    st.success("🟢 Motor de IA: Conectado")
  else:
    st.error("🔴 Motor de IA: Clave no detectada")
  st.info("Rol: **Analista SOC Nivel 2**\nMetodología: **MITRE ATT&CK / D3FEND**")
  st.divider()
  st.caption("Bootcamp Cyber Threat Intelligence & SOC L2")

# ==========================================================
# 1. CARGA DE ARCHIVOS
# ==========================================================
st.markdown("### 📥 1. Ingesta de Telemetría y Logs")
uploaded_file = st.file_uploader(
    "Carga el archivo CSV de telemetría consolidada",
    type=["csv", "txt", "log"],
    help="Admite datasets de eventos Windows/EDR delimitados por ';' o ','",
)

if uploaded_file is not None:
  try:
    df = pd.read_csv(uploaded_file, sep=";")
    if "Event_ID" not in df.columns:
      uploaded_file.seek(0)
      df = pd.read_csv(uploaded_file, sep=",")

    df["Severity"] = df["Severity"].fillna("Informational").astype(str)
    df["Hostname"] = df["Hostname"].fillna("Unknown").astype(str)
    df["Event_ID"] = df["Event_ID"].astype(str)
    df["User"] = df["User"].fillna("SYSTEM").astype(str)
    df["Process_CommandLine"] = df["Process_CommandLine"].fillna("").astype(str)
    st.success(
        f"✅ Dataset cargado: **{len(df):,} eventos** registrados en"
        " telemetría."
    )
  except Exception as e:
    st.error(f"Error crítico al procesar el archivo: {e}")
    st.stop()
else:
  st.info(
      "💡 Por favor sube tu archivo CSV de logs para activar el flujo de"
      " correlación integral."
  )
  st.stop()

# ==========================================================
# 2. SELECCIÓN DESTACADA DEL INCIDENTE Y CORRELACIÓN
# ==========================================================
st.divider()
st.markdown("### 🎯 2. Selector Maestro de Incidentes Correlacionados")
st.markdown(
    "Selecciona a continuación el incidente a investigar. **Toda la plataforma"
    " (Dashboard, Riesgos, Informe y PDF) se sincronizará automáticamente** con"
    " este contexto."
)

# Definición de metadatos de los incidentes maestros presentes en los logs
incident_catalog = {
    "INC-01": {
        "title": (
            "INC-01: Intrusión RDP, Ejecución de LOLBins y Exfiltración de"
            " Finanzas"
        ),
        "hosts": ["APP-SRV01", "FS-SRV01"],
        "severity_badge": "CRÍTICO",
        "badge_class": "badge-critical",
        "vector": (
            "Acceso inicial vía RDP (LogonType=10) con credencial 'admin',"
            " spawn de PowerShell codificado en Base64, enumeración de"
            " privilegios, pivot a recurso compartido \\\\FS-SRV01\\Finance,"
            " compresión con tar.exe y exfiltración a IP 203.0.113.88:443."
        ),
        "filter": lambda d: d[
            (d["Hostname"].isin(["APP-SRV01", "FS-SRV01"]))
            & (
                d["User"].str.contains("admin", case=False, na=False)
                | d["Severity"].isin(["High", "Warning"])
                | d["Process_CommandLine"].str.contains(
                    "powershell|tar|Get-LocalGroupMember", case=False, na=False
                )
            )
        ],
        "risk_level": "CRÍTICO",
        "mitre_category": (
            "Acceso Inicial (T1078), Ejecución (T1059.001), Movimiento Lateral"
            " (T1021.002), Exfiltración (T1048)"
        ),
        "justification": (
            "Inicio de sesión exitoso RDP seguido de ejecución de PowerShell"
            " ofuscado (-EncodedCommand), acceso ilegítimo a"
            " \\\\FS-SRV01\\Finance\\Budget2027.xlsx, staging local con tar.exe"
            " y apertura de socket saliente a IP sospechosa 203.0.113.88."
        ),
        "action_directive": (
            "Aislar perimetralmente de inmediato APP-SRV01 y FS-SRV01. Revocar"
            " credenciales de CORP\\admin. Bloquear IP 203.0.113.88 en firewall"
            " y escalar a DFIR para adquisición de RAM."
        ),
    },
    "INC-02": {
        "title": (
            "INC-02: Ataque de Fuerza Bruta / Password Spraying en Controlador"
            " de Dominio"
        ),
        "hosts": ["DC-01", "DC01"],
        "severity_badge": "ALTO / WARNING",
        "badge_class": "badge-high",
        "vector": (
            "Ráfaga continua de eventos EventID 4625 (Fallas de inicio de"
            " sesión) sobre múltiples cuentas de usuario (jlopez, slopez,"
            " helpdesk, dtorres) en ventanas cortas de tiempo provenientes de"
            " subredes de estaciones de trabajo."
        ),
        "filter": lambda d: d[
            (d["Hostname"].str.contains("DC", case=False, na=False))
            & (
                d["Event_ID"].isin(["4625", "4624", "4672"])
                | d["Severity"].isin(["Warning", "High"])
            )
        ],
        "risk_level": "MEDIO / ALTO",
        "mitre_category": (
            "Credential Access (T1110.003 - Password Spraying / Brute Force)"
        ),
        "justification": (
            "Múltiples eventos 4625 con códigos de error de autenticación en"
            " DC-01 afectando a distintas cuentas de usuario corporativas de"
            " forma secuencial."
        ),
        "action_directive": (
            "Implementar bloqueo temporal de cuentas afectadas, verificar IPs"
            " de origen internas en busca de hosts comprometidos y activar"
            " autenticación multifactor (MFA)."
        ),
    },
    "INC-03": {
        "title": (
            "INC-03: Reconocimiento Web, Fuzzing de APIs y Ejecución Anómala de"
            " Comandos"
        ),
        "hosts": ["WEB-01"],
        "severity_badge": "MEDIO / ALTO",
        "badge_class": "badge-medium",
        "vector": (
            "Escaneo sistemático de endpoints privilegiados (/admin/,"
            " /api/v1/export, /login?user=admin) culminando en la invocación de"
            " 'cmd.exe /c whoami' bajo el proceso del servidor web."
        ),
        "filter": lambda d: d[
            (d["Hostname"] == "WEB-01")
            & (
                d["Process_CommandLine"].str.contains(
                    "admin|api|cmd|whoami", case=False, na=False
                )
                | d["Severity"].isin(["High", "Warning"])
            )
        ],
        "risk_level": "MEDIO / ALTO",
        "mitre_category": (
            "Discovery (T1082 / T1033), Initial Access / Exploit Public-Facing"
            " App (T1190)"
        ),
        "justification": (
            "Secuencia de peticiones web anómalas con parámetros de inyección"
            " seguidas de ejecución anómala de cmd.exe /c whoami en el servidor"
            " WEB-01."
        ),
        "action_directive": (
            "Inspeccionar logs del servicio Web/WAF, terminar procesos"
            " interactivos anómalos en WEB-01 y parchar endpoints vulnerables"
            " expuestos."
        ),
    },
}

# 🎯 PROCURAR SELECCIÓN VISUALMENTE CLARA CON CONTENEDOR TIPO DASHBOARD DE MANDO
with st.container(border=True):
  col_opt1, col_opt2, col_opt3 = st.columns(3)

  with col_opt1:
    st.markdown("#### 🔥 **Incidente 01**")
    st.markdown(
        "<span class='badge-critical'>CRÍTICO</span> **Exfiltración"
        " Finanzas**",
        unsafe_allow_html=True,
    )
    st.caption("**Hosts:** `APP-SRV01`, `FS-SRV01`\n**Vector:** RDP + LOLBins")

  with col_opt2:
    st.markdown("#### ⚠️ **Incidente 02**")
    st.markdown(
        "<span class='badge-high'>ALTO</span> **Fuerza Bruta DC**",
        unsafe_allow_html=True,
    )
    st.caption(
        "**Hosts:** `DC-01`\n**Vector:** Password Spraying (EventID 4625)"
    )

  with col_opt3:
    st.markdown("#### 🌐 **Incidente 03**")
    st.markdown(
        "<span class='badge-medium'>MEDIO</span> **Web Injection**",
        unsafe_allow_html=True,
    )
    st.caption("**Hosts:** `WEB-01`\n**Vector:** API Fuzzing + cmd whoami")

  selected_inc_key = st.radio(
      "**Seleccione el Incidente Activo para enfocar toda la investigación:**",
      options=list(incident_catalog.keys()),
      format_func=lambda k: f"{k} - {incident_catalog[k]['title']}",
      index=0,
      horizontal=True,
  )

# Contexto del incidente activo
inc_meta = incident_catalog[selected_inc_key]

# 🎯 INTEGRIDAD: Creación del DataFrame Contextual que regirá todas las secciones siguientes
df_contexto = inc_meta["filter"](df).copy().sort_values("Timestamp")
if df_contexto.empty:
  # Respaldo de seguridad si el filtro es estricto
  df_contexto = df[df["Hostname"].isin(inc_meta["hosts"])].copy()

# Renderizado de la Kill Chain detallada
st.info(
    f"📍 **Detalle de la Kill Chain para {selected_inc_key}:**\n\n"
    f"{inc_meta['vector']}"
)

with st.expander(
    f"🔎 Ver Telemetría Correlacionada de {selected_inc_key} ({len(df_contexto)} eventos registrados)",
    expanded=True,
):
  st.dataframe(
      df_contexto[[
          "Timestamp",
          "Hostname",
          "Event_ID",
          "User",
          "Source_IP",
          "Destination",
          "Severity",
          "Process_CommandLine",
          "Event_Description",
      ]],
      use_container_width=True,
  )

# Botón de Análisis de IA Contextual
if st.button(f"🤖 Ejecutar Evaluación Asistida por IA sobre {selected_inc_key}"):
  if not client:
    st.error(
        "Clave 'GEMINI_API_KEY' no detectada. Configúrala en los Secrets de"
        " Streamlit Cloud."
    )
  else:
    with st.spinner(
        f"Correlacionando TTPs y generando assessment para"
        f" {selected_inc_key}..."
    ):
      sample_logs = df_contexto.head(25).to_string()
      prompt = f"""
            Actúa como un Analista de Ciberseguridad SOC Nivel 2.
            Analiza la telemetría del incidente correlacionado: {inc_meta['title']}.
            Hosts involucrados: {inc_meta['hosts']}.
            
            Logs empíricos:
            {sample_logs}
            
            Elabora un dictamen técnico profesional:
            1. Hipótesis y Causalidad Temporal (Vector inicial, acciones sobre el objetivo).
            2. TTPs identificados según MITRE ATT&CK.
            3. Nivel de Confianza (Confidence: Alto, Medio o Bajo) justificando la evidencia.
            4. Contramedidas inmediatas según MITRE D3FEND.
            """
      modelos = [
          "gemini-2.0-flash",
          "gemini-1.5-flash",
          "gemini-2.5-flash",
          "gemini-3.8-flash",
      ]
      analisis_ok = None
      for m in modelos:
        try:
          res = client.models.generate_content(model=m, contents=prompt)
          analisis_ok = res.text
          st.session_state[f"ai_eval_{selected_inc_key}"] = analisis_ok
          st.success(
              f"Evaluación completada con éxito utilizando el motor {m}."
          )
          break
        except Exception:
          continue
      if not analisis_ok:
        st.error(
            "Servidores de IA con alta demanda temporal (503). Intenta"
            " nuevamente en unos momentos."
        )

ai_text_actual = st.session_state.get(f"ai_eval_{selected_inc_key}", "")
if ai_text_actual:
  st.markdown(ai_text_actual)

# ==========================================================
# 3. DASHBOARD CONTEXTUAL Y REACTIVO AL INCIDENTE
# ==========================================================
st.divider()
st.markdown(
    f"### 📊 3. Dashboard Operativo: Telemetría de **{selected_inc_key}**"
)
st.caption(
    "Todas las métricas y gráficos reflejan estrictamente el subconjunto de"
    f" datos del incidente seleccionado ({', '.join(inc_meta['hosts'])})."
)

# 🎯 MÉTRICAS 100% DINÁMICAS Y SINCRONIZADAS
m1, m2, m3, m4 = st.columns(4)
m1.metric("Eventos del Incidente", len(df_contexto))
m2.metric(
    "Alertas High / Warning",
    len(
        df_contexto[
            df_contexto["Severity"].isin(["High", "Warning", "Critical"])
        ]
    ),
)
m3.metric("Hosts Comprometidos", df_contexto["Hostname"].nunique())
m4.metric("Usuarios Implicados", df_contexto["User"].nunique())

d_col1, d_col2 = st.columns(2)
with d_col1:
  fig_sev = px.pie(
      df_contexto,
      names="Severity",
      title=f"Distribución de Severidad ({selected_inc_key})",
      color="Severity",
      color_discrete_map={
          "High": "#DC2626",
          "Warning": "#EA580C",
          "Medium": "#D97706",
          "Informational": "#2563EB",
      },
  )
  fig_sev.update_layout(margin=dict(t=40, b=20, l=20, r=20))
  st.plotly_chart(fig_sev, use_container_width=True)

with d_col2:
  top_hosts_data = (
      df_contexto.groupby("Hostname")
      .size()
      .reset_index(name="Volumen_Eventos")
      .sort_values(by="Volumen_Eventos", ascending=False)
  )
  fig_hosts = px.bar(
      top_hosts_data,
      x="Hostname",
      y="Volumen_Eventos",
      color="Volumen_Eventos",
      color_continuous_scale="Reds",
      title=f"Frecuencia de Actividad por Host ({selected_inc_key})",
  )
  fig_hosts.update_layout(margin=dict(t=40, b=20, l=20, r=20))
  st.plotly_chart(fig_hosts, use_container_width=True)

# ==========================================================
# 4. CLASIFICACIÓN DE RIESGOS (REACTIVA AL INCIDENTE)
# ==========================================================
st.divider()
st.markdown(
    f"### ⚖️ 4. Clasificación de Riesgos y Evaluación de Amenazas"
    f" ({selected_inc_key})"
)

# 🎯 CÁLCULO DE RIESGO COHERENTE CON EL INCIDENTE
st.markdown(
    f"**Nivel de Riesgo Evaluado:** `{inc_meta['risk_level']}` | **Hosts"
    f" Evaluados:** `{', '.join(inc_meta['hosts'])}`"
)
st.warning(f"**Directiva de Respuesta Operativa:** {inc_meta['action_directive']}")

# Tabla formal con Categoría MITRE y Justificación Técnica adaptada
risk_table_payload = {
    "Categoría de Amenaza (MITRE)": [
        inc_meta["mitre_category"].split(",")[0],
        inc_meta["mitre_category"].split(",")[1]
        if "," in inc_meta["mitre_category"]
        else "Persistencia / Evasión",
        "Control Operativo / Respuesta",
    ],
    "Justificación / Evidencia Detectada en Logs": [
        inc_meta["justification"],
        f"Telemetría anómala confirmada sobre los activos: {', '.join(inc_meta['hosts'])}.",
        f"Severidad catalogada como {inc_meta['risk_level']} acorde a la matriz de impacto del negocio.",
    ],
    "Nivel de Confianza (Confidence)": ["Alto", "Alto", "Alto"],
    "Decisión Operativa": [
        "Aislamiento de Host / Bloqueo",
        "Revocación de Credenciales",
        "Preservación de Evidencias (DFIR)",
    ],
}
st.dataframe(pd.DataFrame(risk_table_payload), use_container_width=True)

# ==========================================================
# 5. INFORME TÉCNICO DE INCIDENTE (DINÁMICO)
# ==========================================================
st.divider()
st.markdown(
    f"### 📝 5. Informe Técnico de Incidente: **{selected_inc_key}**"
)

# Resumen ejecutivo dinámico basado en el contexto activo
if ai_text_actual:
  primeras_lineas = [
      l.strip()
      for l in ai_text_actual.split("\n")
      if l.strip() and not l.startswith("#")
  ]
  extracto_ai = " ".join(primeras_lineas[:2]) if primeras_lineas else ""
  dynamic_summary = (
      f"Evaluación técnica SOC L2 para {inc_meta['title']}. {extracto_ai}"
  )
else:
  dynamic_summary = (
      f"Durante el monitoreo de seguridad se confirmó el incidente"
      f" {inc_meta['title']}, catalogado con nivel de riesgo"
      f" {inc_meta['risk_level']}. Los activos afectados corresponden a"
      f" {', '.join(inc_meta['hosts'])}, registrando {len(df_contexto)} eventos"
      f" de telemetría correlacionados. Justificación empírica:"
      f" {inc_meta['justification']} Se dispone la directiva inmediata:"
      f" {inc_meta['action_directive']}"
  )

executive_summary = st.text_area(
    "Resumen Ejecutivo del Analista (Editable):",
    value=dynamic_summary,
    height=130,
)
analyst_name = st.text_input("Analista a cargo:", value="Analista SOC Nivel 2")

# ==========================================================
# 6. EXPORTACIÓN EN PDF
# ==========================================================
st.divider()
st.markdown("### 📄 6. Exportar Informe Técnico a PDF")


def generar_pdf(inc_id, inc_titulo, resumen, analista, riesgo, hosts, ai_text):
  buffer = io.BytesIO()
  doc = SimpleDocTemplate(
      buffer,
      pagesize=letter,
      rightMargin=40,
      leftMargin=40,
      topMargin=40,
      bottomMargin=40,
  )
  styles = getSampleStyleSheet()

  title_style = ParagraphStyle(
      "TitleStyle",
      parent=styles["Heading1"],
      fontSize=16,
      textColor=colors.HexColor("#1E3A8A"),
      spaceAfter=12,
  )
  h2_style = ParagraphStyle(
      "H2Style",
      parent=styles["Heading2"],
      fontSize=12,
      textColor=colors.HexColor("#2563EB"),
      spaceBefore=10,
      spaceAfter=6,
  )
  body_style = ParagraphStyle(
      "BodyStyle",
      parent=styles["Normal"],
      fontSize=9.5,
      leading=13,
      textColor=colors.HexColor("#1F2937"),
  )

  story = []
  story.append(
      Paragraph(f"INFORME TÉCNICO DE INCIDENTE - SOC NIVEL 2 ({inc_id})", title_style)
  )
  story.append(
      Paragraph(
          f"<b>Incidente:</b> {inc_titulo}<br/>"
          f"<b>Analista Responsable:</b> {analista} | <b>Nivel de Riesgo:</b> {riesgo} | <b>Activos:</b> {', '.join(hosts)}",
          body_style,
      )
  )
  story.append(Spacer(1, 10))

  story.append(Paragraph("1. Resumen Ejecutivo", h2_style))
  story.append(Paragraph(resumen, body_style))
  story.append(Spacer(1, 10))

  story.append(Paragraph("2. Evaluación Técnica y Correlación de Amenazas", h2_style))
  texto_eval = (
      ai_text.replace("\n", "<br/>")
      if ai_text
      else (
          f"Se analizó la telemetría correspondiente a {inc_id}. La evidencia confirma la afectación de los activos "
          f"{', '.join(hosts)}. Se validaron patrones de comportamiento adversario acorde a MITRE ATT&CK."
      )
  )
  story.append(Paragraph(texto_eval, body_style))
  story.append(Spacer(1, 10))

  story.append(Paragraph("3. Acciones de Mitigación y Respuesta Inmediata", h2_style))
  story.append(Paragraph(f"• Directiva operativa: {inc_meta['action_directive']}", body_style))
  story.append(Paragraph("• Ejecutar aislamiento perimetral de red en los activos comprometidos.", body_style))
  story.append(Paragraph("• Revocar credenciales y forzar cierre de sesiones activas en el Directorio Activo.", body_style))
  story.append(Paragraph("• Escalar a DFIR para preservación de memoria volátil (volatility3) y análisis forense.", body_style))

  doc.build(story)
  buffer.seek(0)
  return buffer


if st.button(f"📥 Generar y Descargar Informe PDF para {selected_inc_key}"):
  pdf_buffer = generar_pdf(
      selected_inc_key,
      inc_meta["title"],
      executive_summary,
      analyst_name,
      inc_meta["risk_level"],
      inc_meta["hosts"],
      ai_text_actual,
  )
  st.download_button(
      label=f"Descargar PDF Oficial ({selected_inc_key})",
      data=pdf_buffer,
      file_name=f"informe_{selected_inc_key.lower()}_soc_l2.pdf",
      mime="application/pdf",
  )
