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
# CONFIGURACIÓN Y TEMA VISUAL ESTILO STELLAR CYBER (OPEN XDR)
# ==========================================================
st.set_page_config(
    page_title="StellarSOC - XDR L2 Workbench",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Inyección de estilos CSS inspirados en la interfaz de Stellar Cyber (Dark Theme)
st.markdown(
    """
<style>
    /* Fondo general oscuro estilo SOC Next-Gen */
    .stApp {
        background-color: #0B132B;
        color: #E2E8F0;
    }
    /* Título principal con brillo Cyber */
    .stellar-header {
        font-size: 2.2rem;
        font-weight: 800;
        background: linear-gradient(90deg, #00F0FF, #3B82F6, #10B981);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 0.2rem;
    }
    .stellar-sub {
        font-size: 1rem;
        color: #94A3B8;
        margin-bottom: 1.5rem;
    }
    /* Tarjetas de Métricas XDR */
    div[data-testid="stMetric"] {
        background-color: #1C2541;
        border: 1px solid #3A506B;
        padding: 15px;
        border-radius: 10px;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.3);
    }
    div[data-testid="stMetricLabel"] {
        color: #94A3B8 !important;
        font-weight: 600;
    }
    div[data-testid="stMetricValue"] {
        color: #00F0FF !important;
        font-family: monospace;
        font-size: 1.9rem;
    }
    /* Cajas y Contenedores */
    div[data-testid="stVerticalBlock"] > div[data-testid="stContainer"] {
        background-color: #111D4A;
        border: 1px solid #1E3A8A;
        border-radius: 10px;
        padding: 18px;
    }
    /* Badges de Severidad */
    .badge-critical {
        background-color: #EF4444;
        color: #FFFFFF;
        padding: 3px 10px;
        border-radius: 12px;
        font-size: 0.8rem;
        font-weight: bold;
    }
    .badge-high {
        background-color: #F97316;
        color: #FFFFFF;
        padding: 3px 10px;
        border-radius: 12px;
        font-size: 0.8rem;
        font-weight: bold;
    }
    .badge-medium {
        background-color: #EAB308;
        color: #1E293B;
        padding: 3px 10px;
        border-radius: 12px;
        font-size: 0.8rem;
        font-weight: bold;
    }
</style>
""",
    unsafe_allow_html=True,
)

st.markdown(
    "<div class='stellar-header'>⚡ STELLAR-XDR | SOC Nivel 2 Incident"
    " Workbench</div>",
    unsafe_allow_html=True,
)
st.markdown(
    "<div class='stellar-sub'>Consola Operativa Multicapa con IA: Triage,"
    " Correlación de Kill Chain y Detección de Amenazas Avanzadas.</div>",
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

# Sidebar estilo Plataforma de Seguridad
with st.sidebar:
  st.image(
      "[suspicious link removed]", width=64
  )
  st.markdown("### **Panel de Control XDR**")
  if api_key:
    st.success("🟢 IA Engine: Activo")
  else:
    st.error("🔴 IA Engine: Clave ausente")
  st.markdown("---")
  st.markdown("**Plataforma:** Stellar Cyber Style")
  st.markdown("**Metodología:** MITRE ATT&CK & D3FEND")
  st.markdown("**Analista:** Nivel 2 (Triage Avanzado)")

# ==========================================================
# 1. CARGA DE ARCHIVOS
# ==========================================================
st.markdown("### 📥 1. Ingesta de Telemetría (Sensor Logs)")
uploaded_file = st.file_uploader(
    "Cargar dataset consolidado de seguridad (.CSV)",
    type=["csv", "txt", "log"],
    help="Admite archivos de logs delimitados por ';' o ','",
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
    df["Source_IP"] = df["Source_IP"].fillna("N/A").astype(str)
    df["Destination"] = df["Destination"].fillna("Local").astype(str)
    df["Process_CommandLine"] = df["Process_CommandLine"].fillna("").astype(str)
    st.success(
        f"✅ Telemetría ingestada exitosamente: **{len(df):,} eventos** listos"
        " para correlación."
    )
  except Exception as e:
    st.error(f"Error al procesar el archivo: {e}")
    st.stop()
else:
  st.info("💡 Sube tu archivo CSV de logs para inicializar el motor de triage.")
  st.stop()

# ==========================================================
# 2. CATÁLOGO COMPLETO DE INCIDENTES Y SELECTOR LIMPIO
# ==========================================================
st.markdown("---")
st.markdown("### 🎯 2. Selector Maestro de Incidentes Correlacionados")

# Catálogo completo con los 4 incidentes reales presentes en el archivo
catalog_incidentes = {
    "INC-01": {
        "title": "INC-01: Intrusión RDP, LOLBins y Exfiltración de Finanzas",
        "badge": "CRÍTICO",
        "attacker": (
            "203.0.113.88 (C2) / Cuenta comprometida: CORP\\admin"
            " (10.10.1.14)"
        ),
        "target": "APP-SRV01 y FS-SRV01 (Recurso \\\\FS-SRV01\\Finance)",
        "hosts": ["APP-SRV01", "FS-SRV01"],
        "kill_chain": (
            "1. Acceso RDP exitoso (LogonType=10) en APP-SRV01 -> 2. Invocación"
            " de PowerShell ofuscado (-EncodedCommand) -> 3. Movimiento lateral"
            " hacia FS-SRV01 accediendo a Budget2027.xlsx -> 4. Empaquetamiento"
            " con tar.exe -> 5. Exfiltración saliente a IP 203.0.113.88:443."
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
        "mitre_technique": (
            "T1078 (Valid Accounts), T1059.001 (PowerShell), T1021.002 (SMB"
            " Shares), T1048 (Exfiltration Over Alternative Protocol)"
        ),
        "justification": (
            "Correlación confirmada de acceso RDP interactivo seguido de"
            " staging de datos confidenciales y apertura de socket de salida a"
            " IP externa no autorizada."
        ),
        "action": (
            "Aislar de la red APP-SRV01 y FS-SRV01. Bloquear IP 203.0.113.88 en"
            " firewall perimetral y revocar credenciales de CORP\\admin."
        ),
    },
    "INC-02": {
        "title": (
            "INC-02: Fuerza Bruta / Password Spraying en Directorio Activo"
        ),
        "badge": "ALTO",
        "attacker": "Múltiples estaciones internas (10.10.1.22, 10.10.2.15)",
        "target": "Controlador de Dominio DC-01 (Cuentas: jlopez, slopez, helpdesk)",
        "hosts": ["DC-01", "DC01"],
        "kill_chain": (
            "Ráfaga continua y secuencial de eventos EventID 4625 (Logon"
            " Failure) en ventanas de segundos, evidenciando un intento"
            " automatizado de adivinación o pulverización de contraseñas."
        ),
        "filter": lambda d: d[
            (d["Hostname"].str.contains("DC", case=False, na=False))
            & (
                d["Event_ID"].isin(["4625", "4624", "4672"])
                | d["Severity"].isin(["Warning", "High"])
            )
        ],
        "risk_level": "MEDIO / ALTO",
        "mitre_technique": (
            "T1110.003 (Password Spraying), T1110.001 (Password Guessing)"
        ),
        "justification": (
            "Elevado ratio de anomalías de autenticación fallida concentradas"
            " sobre el servicio de autenticación corporativo."
        ),
        "action": (
            "Bloquear temporalmente las cuentas de usuario afectadas, forzar"
            " cambio de credenciales y auditar estaciones de origen en busca de"
            " malware."
        ),
    },
    "INC-03": {
        "title": "INC-03: Fuzzing Web y Ejecución de Comandos Anómalos",
        "badge": "MEDIO / ALTO",
        "attacker": "IP Externa 198.51.100.77 (Tráfico HTTP/Proxy)",
        "target": "Servidor Web WEB-01 (IIS / Web Application)",
        "hosts": ["WEB-01"],
        "kill_chain": (
            "Escaneo masivo de rutas no autorizadas (/admin/, /api/v1/export)"
            " seguido de ejecución de subproceso de consola 'cmd.exe /c whoami'"
            " bajo el árbol del servidor web."
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
        "mitre_technique": (
            "T1190 (Exploit Public-Facing Application), T1059.003 (Windows"
            " Command Shell), T1033 (System Owner/User Discovery)"
        ),
        "justification": (
            "Pivoteo directo desde peticiones HTTP no autorizadas hacia"
            " ejecución interactiva en el servidor web."
        ),
        "action": (
            "Bloquear IP atacante en WAF/Proxy, terminar procesos cmd.exe"
            " activos en WEB-01 y auditar código de la aplicación web."
        ),
    },
    "INC-04": {
        "title": "INC-04: Actividad de Ransomware y Destrucción de Backups",
        "badge": "CRÍTICO",
        "attacker": (
            "WS-023 (10.10.1.44) / Cuenta usurpada: CORP\\backupsvc"
        ),
        "target": "FS-SRV01 (Cifrado masivo) y WS-023 (Destrucción VSS)",
        "hosts": ["WS-023", "FS-SRV01"],
        "kill_chain": (
            "1. Ejecución de PowerShell codificado en WS-023 -> 2. Acceso"
            " simultáneo y masivo a decenas de archivos en \\\\FS-SRV01\\Finance"
            " -> 3. Ejecución de 'vssadmin.exe delete shadows /all /quiet' para"
            " impedir la recuperación de datos."
        ),
        "filter": lambda d: d[
            (
                (d["Hostname"].isin(["WS-023", "FS-SRV01"]))
                & (
                    d["User"].str.contains("backupsvc", case=False, na=False)
                    | d["Process_CommandLine"].str.contains(
                        "vssadmin|powershell", case=False, na=False
                    )
                )
            )
            | (
                (d["Hostname"] == "FS-SRV01")
                & (d["Severity"].isin(["High", "Warning"]))
            )
        ],
        "risk_level": "CRÍTICO",
        "mitre_technique": (
            "T1486 (Data Encrypted for Impact), T1490 (Inhibit System"
            " Recovery), T1078 (Valid Accounts)"
        ),
        "justification": (
            "Destrucción intencional de copias de instantánea de volumen"
            " (VSS) combinada con lectura masiva acelerada de documentos"
            " financieros."
        ),
        "action": (
            "Aislar de emergencia WS-023 y el servidor FS-SRV01. Suspender"
            " cuenta CORP\\backupsvc y activar playbooks de mitigación de"
            " Ransomware."
        ),
    },
}

# 🎯 SELECTOR LIMPIO QUE INVITA A SELECCIONAR EL INCIDENTE
selected_inc_key = st.selectbox(
    "👉 **Selecciona el Incidente de Seguridad que deseas investigar y"
    " correlacionar:**",
    options=list(catalog_incidentes.keys()),
    format_func=lambda k: (
        f"[{catalog_incidentes[k]['badge']}] {catalog_incidentes[k]['title']}"
    ),
    index=0,
)

inc_meta = catalog_incidentes[selected_inc_key]

# 🎯 RESUMEN VISUAL DEL INCIDENTE ACTIVO TIPO STELLAR CYBER
with st.container():
  c1, c2 = st.columns([3, 1])
  with c1:
    st.markdown(f"#### 🔎 **{inc_meta['title']}**")
    st.markdown(
        f"**🔴 Atacante / Origen:** `{inc_meta['attacker']}` &nbsp;|&nbsp; "
        f"**🎯 Víctima / Objetivo:** `{inc_meta['target']}`"
    )
    st.markdown(f"**⚡ Kill Chain Reconstruida:** {inc_meta['kill_chain']}")
  with c2:
    st.markdown(f"**Nivel de Severidad:**")
    if inc_meta["badge"] == "CRÍTICO":
      st.markdown(
          f"<span class='badge-critical'>{inc_meta['badge']}</span>",
          unsafe_allow_html=True,
      )
    else:
      st.markdown(
          f"<span class='badge-high'>{inc_meta['badge']}</span>",
          unsafe_allow_html=True,
      )
    st.caption(f"Hosts: {', '.join(inc_meta['hosts'])}")

# DATASET CONTEXTUAL DEL INCIDENTE
df_incidente = inc_meta["filter"](df).copy().sort_values("Timestamp")
if df_incidente.empty:
  df_incidente = df[df["Hostname"].isin(inc_meta["hosts"])].copy()

# 🎯 TELEMETRÍA DETALLADA CON IP ATACANTE Y VÍCTIMA
with st.expander(
    f"📋 Telemetría Crítica Correlacionada ({len(df_incidente)} registros)"
    " - Detalle Atacante vs. Víctima",
    expanded=True,
):
  st.dataframe(
      df_incidente[[
          "Timestamp",
          "Source_IP",
          "Hostname",
          "Destination",
          "User",
          "Event_ID",
          "Severity",
          "Process_CommandLine",
          "Event_Description",
      ]].rename(
          columns={
              "Source_IP": "IP Origen (Atacante)",
              "Hostname": "Host Víctima",
              "Destination": "Destino / Recurso",
          }
      ),
      use_container_width=True,
  )

# Botón de Análisis de IA
if st.button(f"🤖 Ejecutar Análisis Asistido por IA sobre {selected_inc_key}"):
  if not client:
    st.error(
        "Clave 'GEMINI_API_KEY' no detectada en Secrets. Configúrala en"
        " Streamlit Cloud."
    )
  else:
    with st.spinner(f"Analizando TTPs de {selected_inc_key} con IA..."):
      sample_logs = df_incidente.head(25).to_string()
      prompt = f"""
            Actúa como un Analista de Ciberseguridad SOC Nivel 2.
            Analiza la telemetría del incidente: {inc_meta['title']}.
            Atacante: {inc_meta['attacker']} | Víctima: {inc_meta['target']}
            
            Logs de telemetría:
            {sample_logs}
            
            Genera un assessment técnico conciso:
            1. Hipótesis del vector y causalidad temporal.
            2. Mapeo TTPs MITRE ATT&CK.
            3. Confidence Level (Alto/Medio/Bajo).
            4. Contramedidas defensivas inmediatas (MITRE D3FEND).
            """
      for m in [
          "gemini-2.0-flash",
          "gemini-1.5-flash",
          "gemini-2.5-flash",
          "gemini-3.8-flash",
      ]:
        try:
          res = client.models.generate_content(model=m, contents=prompt)
          st.session_state[f"ai_report_{selected_inc_key}"] = res.text
          st.success(f"Análisis completado exitosamente con motor {m}.")
          break
        except Exception:
          continue

ai_text_actual = st.session_state.get(f"ai_report_{selected_inc_key}", "")
if ai_text_actual:
  st.markdown(ai_text_actual)

# ==========================================================
# 3. DASHBOARD TOTALMENTE DINÁMICO (FILTROS REACTIVOS)
# ==========================================================
st.markdown("---")
st.markdown(
    f"### 📊 3. Dashboard Interactivo de Telemetría ({selected_inc_key})"
)

# CONTROLES INTERACTIVOS DE FILTRO
with st.container():
  col_f1, col_f2 = st.columns(2)
  with col_f1:
    sevs_disponibles = sorted(list(df_incidente["Severity"].unique()))
    filtro_sev = st.multiselect(
        "Filtrar por Nivel de Severidad:",
        options=sevs_disponibles,
        default=sevs_disponibles,
    )
  with col_f2:
    hosts_en_inc = ["Todos los del incidente"] + sorted(
        list(df_incidente["Hostname"].unique())
    )
    filtro_host = st.selectbox(
        "Profundizar (Drill-Down) en Host específico:", hosts_en_inc
    )

# APLICAR FILTROS REACTIVOS AL DATASET DEL DASHBOARD
df_dash = df_incidente[df_incidente["Severity"].isin(filtro_sev)].copy()
if filtro_host != "Todos los del incidente":
  df_dash = df_dash[df_dash["Hostname"] == filtro_host]

# 🎯 TARJETAS DE MÉTRICAS DINÁMICAS (SE ACTUALIZAN AL CAMBIAR FILTROS)
m1, m2, m3, m4 = st.columns(4)
m1.metric("Total Eventos Filtrados", len(df_dash))
m2.metric(
    "Alertas Críticas / High",
    len(df_dash[df_dash["Severity"].isin(["High", "Critical"])]),
)
m3.metric("Hosts Involucrados", df_dash["Hostname"].nunique())
m4.metric("Usuarios Activos", df_dash["User"].nunique())

d_col1, d_col2 = st.columns(2)
with d_col1:
  if not df_dash.empty:
    fig_pie = px.pie(
        df_dash,
        names="Severity",
        title="Distribución de Severidad en la Selección",
        color="Severity",
        color_discrete_map={
            "High": "#EF4444",
            "Warning": "#F97316",
            "Medium": "#EAB308",
            "Informational": "#3B82F6",
        },
        template="plotly_dark",
    )
    st.plotly_chart(fig_pie, use_container_width=True)
  else:
    st.info("Sin eventos para el filtro seleccionado.")

with d_col2:
  if not df_dash.empty:
    top_h = (
        df_dash.groupby("Hostname")
        .size()
        .reset_index(name="Eventos")
        .sort_values(by="Eventos", ascending=False)
    )
    fig_bar = px.bar(
        top_h,
        x="Hostname",
        y="Eventos",
        color="Eventos",
        color_continuous_scale="Viridis",
        title="Frecuencia de Alertas por Activo (Dinámico)",
        template="plotly_dark",
    )
    st.plotly_chart(fig_bar, use_container_width=True)

# ==========================================================
# 4. CLASIFICACIÓN DE RIESGOS (SINCRONIZADA CON EL INCIDENTE)
# ==========================================================
st.markdown("---")
st.markdown(
    f"### ⚖️ 4. Matriz de Clasificación de Riesgos ({selected_inc_key})"
)

st.markdown(
    f"**Nivel de Riesgo Global Asignado:** `{inc_meta['risk_level']}` |"
    f" **Activos Comprometidos:** `{', '.join(inc_meta['hosts'])}`"
)
st.warning(f"**Directiva de Respuesta Operativa:** {inc_meta['action']}")

risk_matrix_display = {
    "Categoría de Amenaza (MITRE)": [
        inc_meta["mitre_technique"].split(",")[0],
        inc_meta["mitre_technique"].split(",")[1]
        if "," in inc_meta["mitre_technique"]
        else "Persistencia / Evasión",
        "Control Operativo de Seguridad",
    ],
    "Justificación / Evidencia Empírica en Logs": [
        inc_meta["justification"],
        f"Afectación confirmada en los activos víctima: {', '.join(inc_meta['hosts'])}.",
        f"Acción coordinada acorde a la criticidad {inc_meta['risk_level']}.",
    ],
    "Nivel de Confianza (Confidence)": ["Alto", "Alto", "Alto"],
    "Decisión Operativa Inmediata": [
        "Aislamiento de Host / Bloqueo Firewall",
        "Revocación de Credenciales en AD",
        "Preservación de Evidencias (DFIR L3)",
    ],
}
st.dataframe(pd.DataFrame(risk_matrix_display), use_container_width=True)

# ==========================================================
# 5. INFORME TÉCNICO DE INCIDENTE
# ==========================================================
st.markdown("---")
st.markdown(
    f"### 📝 5. Informe Técnico de Incidente: **{selected_inc_key}**"
)

if ai_text_actual:
  primeras = [
      l.strip()
      for l in ai_text_actual.split("\n")
      if l.strip() and not l.startswith("#")
  ]
  extracto = " ".join(primeras[:2]) if primeras else ""
  summary_val = f"Dictamen Técnico SOC L2 para {inc_meta['title']}. {extracto}"
else:
  summary_val = (
      f"Durante las operaciones de monitoreo se confirmó el incidente"
      f" {inc_meta['title']} con nivel de riesgo {inc_meta['risk_level']}.\n"
      f"Vector Atacante: {inc_meta['attacker']} | Activos Víctima:"
      f" {inc_meta['target']}.\n"
      f"Evidencia: {inc_meta['justification']}\n"
      f"Directiva de Contención: {inc_meta['action']}"
  )

executive_summary = st.text_area(
    "Resumen Ejecutivo del Analista (Editable):", value=summary_val, height=130
)
analyst_name = st.text_input("Analista Responsable:", value="Analista SOC Nivel 2")

# ==========================================================
# 6. EXPORTACIÓN A PDF
# ==========================================================
st.markdown("---")
st.markdown("### 📄 6. Exportación de Informe Técnico a PDF")


def generar_pdf(
    inc_id, inc_titulo, resumen, analista, riesgo, attacker, target, ai_text
):
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
      textColor=colors.HexColor("#0B132B"),
      spaceAfter=12,
  )
  h2_style = ParagraphStyle(
      "H2Style",
      parent=styles["Heading2"],
      fontSize=12,
      textColor=colors.HexColor("#1E3A8A"),
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
      Paragraph(
          f"INFORME TÉCNICO DE INCIDENTE - STELLAR SOC L2 ({inc_id})",
          title_style,
      )
  )
  story.append(
      Paragraph(
          f"<b>Incidente:</b> {inc_titulo}<br/>"
          f"<b>Analista:</b> {analista} | <b>Nivel de Riesgo:</b> {riesgo}<br/>"
          f"<b>Atacante / Origen:</b> {attacker}<br/>"
          f"<b>Víctima / Objetivo:</b> {target}",
          body_style,
      )
  )
  story.append(Spacer(1, 10))

  story.append(Paragraph("1. Resumen Ejecutivo del Incidente", h2_style))
  story.append(Paragraph(resumen.replace("\n", "<br/>"), body_style))
  story.append(Spacer(1, 10))

  story.append(
      Paragraph("2. Evaluación Técnica y Correlación de Kill Chain", h2_style)
  )
  texto_ai = (
      ai_text.replace("\n", "<br/>")
      if ai_text
      else (
          f"Se analizó la telemetría del incidente {inc_id}. La correlación confirma la afectación de los activos "
          f"{target} por parte de {attacker}. Se identificaron TTPs acordes a MITRE ATT&CK."
      )
  )
  story.append(Paragraph(texto_ai, body_style))
  story.append(Spacer(1, 10))

  story.append(Paragraph("3. Acciones de Contención y Respuesta", h2_style))
  story.append(
      Paragraph(
          f"• Directiva Inmediata: {inc_meta['action']}", body_style
      )
  )
  story.append(
      Paragraph(
          "• Ejecutar aislamiento de red en los activos identificados como víctima.",
          body_style,
      )
  )
  story.append(
      Paragraph(
          "• Bloquear IPs y hashes maliciosos en firewall y EDR.", body_style
      )
  )
  story.append(
      Paragraph(
          "• Escalar a DFIR / Nivel 3 para adquisición de memoria volátil y análisis forense.",
          body_style,
      )
  )

  doc.build(story)
  buffer.seek(0)
  return buffer


if st.button(f"📥 Descargar Informe Técnico Oficial en PDF ({selected_inc_key})"):
  pdf_buffer = generar_pdf(
      selected_inc_key,
      inc_meta["title"],
      executive_summary,
      analyst_name,
      inc_meta["risk_level"],
      inc_meta["attacker"],
      inc_meta["target"],
      ai_text_actual,
  )
  st.download_button(
      label=f"Descargar PDF Oficial ({selected_inc_key})",
      data=pdf_buffer,
      file_name=f"informe_{selected_inc_key.lower()}_soc_l2.pdf",
      mime="application/pdf",
  )
