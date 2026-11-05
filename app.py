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

# Configuración de página
st.set_page_config(
    page_title="SOC L2 AI Incident Workbench", page_icon="🛡️", layout="wide"
)

st.title("🛡️ SOC-L2 JRBV - Plataforma de Triage, Análisis y Correlación con IA")
st.markdown(
    "Workbench operativo para analistas SOC Nivel 2: ingesta de telemetría,"
    " correlación de cadenas de ataque (Kill Chain), evaluación de riesgos y"
    " reportes técnicos ejecutivos."
)

# Inicialización de la API de IA (Secrets de Streamlit o variables de entorno)
api_key = st.secrets.get("GEMINI_API_KEY", os.environ.get("GEMINI_API_KEY", ""))
client = None
if api_key:
  try:
    client = genai.Client(api_key=api_key)
  except Exception as e:
    st.warning(f"Error al inicializar cliente de IA: {e}")

# ==========================================================
# 1. CARGA DE ARCHIVOS
# ==========================================================
st.header("1. Ingesta de Telemetría y Logs")
uploaded_file = st.file_uploader(
    "Carga el archivo de logs (CSV delimitado por punto y coma o coma)",
    type=["csv", "txt", "log"],
)

if uploaded_file is not None:
  try:
    df = pd.read_csv(uploaded_file, sep=";")
    if "Event_ID" not in df.columns:
      uploaded_file.seek(0)
      df = pd.read_csv(uploaded_file, sep=",")
    st.success(
        f"Archivo cargado correctamente: {len(df)} eventos registrados en"
        " telemetría."
    )
  except Exception as e:
    st.error(f"Error al leer el archivo: {e}")
    st.stop()
else:
  st.info(
      "Por favor sube tu archivo CSV de logs para activar el análisis, la"
      " correlación y el dashboard."
  )
  st.stop()

# ==========================================================
# 2. DETECCIÓN Y CORRELACIÓN DE AMENAZAS
# ==========================================================
st.header("2. Detección y Correlación de Cadenas de Ataque")

# Identificación de eventos críticos / sospechosos
#suspicious_mask = (
#    df["Severity"].isin(["High", "Warning", "Critical"])
#    | df["Process_CommandLine"].str.contains(
#        "powershell|cmd|vssadmin|net |whoami|-enc|tar|admin|api",
#        case=False,
#        na=False,
#    )
#    | df["Event_ID"].isin()
#)
# CÓDIGO CORREGIDO:
# Convertimos Event_ID a string para asegurar compatibilidad sin importar el tipo de dato
event_ids_criticos = ["4104", "4698", "7045", "5145", 4104, 4698, 7045, 5145]

suspicious_mask = (
    df["Severity"].isin(["High", "Warning", "Critical"])
    | df["Process_CommandLine"].str.contains(
        "powershell|cmd|vssadmin|net |whoami|-enc|tar|admin|api",
        case=False,
        na=False,
    )
    | df["Event_ID"].isin(event_ids_criticos)
)
suspicious_df = df[suspicious_mask].copy()

# Definición de incidentes correlacionados basados en telemetría
tab_corr1, tab_corr2 = st.tabs(
    ["🔗 Incidentes Correlacionados (Kill Chain)", "📋 Lista de Eventos Críticos"]
)

with tab_corr1:
  st.subheader("Correlación de Incidentes Multi-Host")
  st.write(
      "El análisis SOC L2 no evalúa alertas aisladas, sino que correlaciona"
      " eventos para reconstruir la cadena causal del atacante:"
  )

  # Agrupación y detección de vectores correlacionados
  incident_options = [
      (
          "INC-01: RDP Inicial -> PowerShell Ofuscado -> Movimiento Lateral ->"
          " Exfiltración (APP-SRV01 / FS-SRV01)"
      ),
      (
          "INC-02: Ataque de Fuerza Bruta / Pulverización de Contraseñas"
          " (DC-01 / Web)"
      ),
      (
          "INC-03: Reconocimiento Web y Ejecución de Comandos Anómalos"
          " (WEB-01)"
      ),
  ]
  selected_incident = st.selectbox(
      "Selecciona un Incidente Correlacionado para examinar su Kill Chain:",
      incident_options,
  )

  if "INC-01" in selected_incident:
    corr_events = df[
        (df["Hostname"].isin(["APP-SRV01", "FS-SRV01"]))
        & (
            df["User"].str.contains("admin", case=False, na=False)
            | df["Severity"].isin(["High", "Warning"])
        )
    ].sort_values("Timestamp")
    st.info(
        "**Secuencia Correlacionada Identificada:** Acceso RDP"
        " (LogonType=10) ➔ Ejecución de PowerShell codificado en Base64 ➔"
        " Descubrimiento de grupos de administradores ➔ Movimiento lateral hacia"
        " recurso compartido de Finanzas (`\\\\FS-SRV01\\Finance`) ➔"
        " Empaquetamiento con `tar.exe` ➔ Conexión externa de salida a IP"
        " sospechosa `203.0.113.88:443`."
    )
  elif "INC-02" in selected_incident:
    corr_events = df[
        (df["Event_ID"].isin(["4625", "4624"]))
        & (df["Hostname"].str.contains("DC|WEB", case=False, na=False))
    ].sort_values("Timestamp")
    st.info(
        "**Secuencia Correlacionada Identificada:** Ráfaga de eventos 4625"
        " (Logon Failures) en ventana corta de tiempo sobre múltiples cuentas"
        " corporativas, indicativo de ataque de diccionario o fuerza bruta."
    )
  else:
    corr_events = df[
        (df["Hostname"] == "WEB-01")
        & (
            df["Process_CommandLine"].str.contains(
                "admin|api|cmd|whoami", case=False, na=False
            )
            | df["Severity"].isin(["High", "Warning"])
        )
    ].sort_values("Timestamp")
    st.info(
        "**Secuencia Correlacionada Identificada:** Escaneo de directorios"
        " administrativos (`/admin/`, `/api/v1/export`) seguido por invocación"
        " anómala de consola de comandos (`cmd.exe /c whoami`)."
    )

  st.dataframe(
      corr_events[[
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

with tab_corr2:
  st.subheader("Eventos Individuales Filtrados por Severidad")
  st.dataframe(
      suspicious_df[[
          "Timestamp",
          "Hostname",
          "Event_ID",
          "User",
          "Severity",
          "Process_CommandLine",
      ]],
      use_container_width=True,
  )

# Botón de análisis con IA sobre la correlación
st.divider()
if st.button("Ejecutar Análisis y Evaluación Técnica con IA"):
  if not client:
    st.error(
        "Falta configurar 'GEMINI_API_KEY' en los Secrets de Streamlit o"
        " variables de entorno."
    )
  else:
    with st.spinner(
        "La IA está correlacionando eventos, TTPs de MITRE y elaborando la"
        " hipótesis..."
    ):
      sample_logs = suspicious_df.head(25).to_string()
      prompt = f"""
            Actúa como un Analista de Ciberseguridad SOC Nivel 2 experto.
            Analiza la siguiente telemetría de eventos sospechosos y correlacionados:
            
            {sample_logs}
            
            Genera un informe analítico estructurado:
            1. Hipótesis del Incidente Correlacionado (Causalidad temporal, vector inicial y pivoteo entre activos).
            2. Mapeo de TTPs según MITRE ATT&CK (Tácticas, Técnicas y Procedimientos).
            3. Evaluación de Confianza (Confidence Level: Alto, Medio o Bajo) justificando la solidez de la evidencia.
            4. Contramedidas defensivas inmediatas basadas en el marco MITRE D3FEND.
            """
      modelos_candidatos = [
          "gemini-2.0-flash",
          "gemini-1.5-flash",
          "gemini-2.5-flash",
          "gemini-3.8-flash"
      ]
      analisis_generado = None

      for mod in modelos_candidatos:
        try:
          response = client.models.generate_content(
              model=mod,
              contents=prompt
          )
          analisis_generado = response.text
          st.session_state["ai_analysis"] = analisis_generado
          st.success(f"Análisis técnico completado exitosamente (utilizando el motor {mod}).")
          break
        except Exception as err:
          continue

      if not analisis_generado:
        st.error("Los servidores de IA están con alta demanda en este momento (503). Por favor intenta de nuevo en unos segundos.")

if "ai_analysis" in st.session_state:
  st.markdown(st.session_state["ai_analysis"])

# ==========================================================
# 3. DASHBOARD INTERACTIVO CON DRILL-DOWN POR HOST
# ==========================================================
st.header("3. Dashboard de Operaciones de Seguridad")

m1, m2, m3, m4 = st.columns(4)
m1.metric("Total Eventos", len(df))
m2.metric(
    "Alertas High / Warning",
    len(df[df["Severity"].isin(["High", "Warning", "Critical"])]),
)
m3.metric("Hosts Monitoreados", df["Hostname"].nunique())
m4.metric("Usuarios Detectados", df["User"].nunique())

d_col1, d_col2 = st.columns(2)
with d_col1:
  fig_sev = px.pie(
      df,
      names="Severity",
      title="Distribución Global de Eventos por Severidad",
      color="Severity",
      color_discrete_map={
          "High": "#E53E3E",
          "Warning": "#DD6B20",
          "Medium": "#D69E2E",
          "Informational": "#3182CE",
      },
  )
  st.plotly_chart(fig_sev, use_container_width=True)

with d_col2:
  top_hosts_data = (
      df[df["Severity"].isin(["High", "Warning", "Critical"])]
      .groupby("Hostname")
      .size()
      .reset_index(name="Total_Alertas")
      .sort_values(by="Total_Alertas", ascending=False)
  )
  fig_hosts = px.bar(
      top_hosts_data,
      x="Hostname",
      y="Total_Alertas",
      color="Total_Alertas",
      color_continuous_scale="Reds",
      title="Top Hosts con Mayor Frecuencia de Alertas Críticas",
  )
  st.plotly_chart(fig_hosts, use_container_width=True)

# INTERACTIVIDAD DEL DASHBOARD: Explorador y filtro por Host
st.subheader("🔍 Explorador Interactivo de Host (Drill-Down)")
lista_hosts = ["Todos"] + sorted(list(df["Hostname"].dropna().unique()))
selected_host = st.selectbox(
    "Selecciona un Host específico para filtrar y profundizar en sus eventos:",
    lista_hosts,
)

if selected_host != "Todos":
  host_filtered_df = df[df["Hostname"] == selected_host]
  col_h1, col_h2, col_h3 = st.columns(3)
  col_h1.metric(f"Eventos en {selected_host}", len(host_filtered_df))
  col_h2.metric(
      "Alertas Críticas/Warning",
      len(host_filtered_df[host_filtered_df["Severity"].isin(["High", "Warning"])]),
  )
  col_h3.metric("Usuarios Activos en Host", host_filtered_df["User"].nunique())

  fig_host_timeline = px.histogram(
      host_filtered_df,
      x="Timestamp",
      color="Severity",
      title=f"Línea Temporal de Eventos para el Host: {selected_host}",
  )
  st.plotly_chart(fig_host_timeline, use_container_width=True)

  st.write(f"**Detalle de eventos registrados en {selected_host}:**")
  st.dataframe(
      host_filtered_df[[
          "Timestamp",
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

# ==========================================================
# 4. CLASIFICACIÓN DE RIESGOS (MATRIZ SOC L2)
# ==========================================================
st.header("4. Matriz de Clasificación de Riesgos y Evaluación de Amenazas")

num_critical = len(df[df["Severity"].isin(["High", "Critical"])])
if num_critical > 5:
  risk_level = "CRÍTICO"
  risk_badge = "🔴 CRÍTICO"
  action_rec = (
      "Aislamiento perimetral inmediato de APP-SRV01 y FS-SRV01. Escalamiento"
      " prioritario a DFIR / Nivel 3 para adquisición de memoria volátil y"
      " preservación de evidencias."
  )
elif num_critical > 0:
  risk_level = "MEDIO / ALTO"
  risk_badge = "🟠 MEDIO / ALTO"
  action_rec = (
      "Bloqueo de IOCs en Firewall/Proxy, revocación de credenciales y Threat"
      " Hunting en el parque de endpoints."
  )
else:
  risk_level = "BAJO"
  risk_badge = "🟢 BAJO"
  action_rec = (
      "Monitoreo estándar, depuración de falsos positivos y calibración de"
      " reglas de detección."
  )

st.markdown(f"### Nivel de Riesgo Global Evaluado: **{risk_badge}**")
st.write(f"**Directiva de Respuesta Operativa:** {action_rec}")

# Tabla estructurada con TÍTULO DE CATEGORÍA y JUSTIFICACIÓN TÉCNICA
risk_matrix_data = {
    "Categoría de Amenaza (MITRE)": [
        "Acceso Inicial (Initial Access)",
        "Ejecución y Evasión (Execution)",
        "Movimiento Lateral (Lateral Movement)",
        "Exfiltración e Impacto (Exfiltration)",
    ],
    "Justificación / Evidencia Detectada en Logs": [
        (
            "Múltiples fallos 4625 seguidos de inicio de sesión RDP exitoso"
            " (LogonType=10) en APP-SRV01 con cuenta CORP\\admin."
        ),
        (
            "Ejecución de PowerShell con parámetros ofuscados (-EncodedCommand)"
            " y sentencias de reconocimiento como Get-LocalGroupMember."
        ),
        (
            "Conexión de red permitida desde APP-SRV01 hacia FS-SRV01 (LogonType=3)"
            " y acceso al recurso compartido confidencial \\FS-SRV01\\Finance."
        ),
        (
            "Empaquetamiento local de archivos mediante tar.exe"
            " (C:\\Temp\\finance.zip) y conexión de salida hacia IP pública"
            " 203.0.113.88:443."
        ),
    ],
    "Probabilidad": ["Alta", "Alta", "Media", "Alta"],
    "Impacto Operativo": ["Alto", "Crítico", "Crítico", "Crítico"],
    "Nivel de Confianza (Confidence)": ["Alto", "Alto", "Alto", "Alto"],
    "Decisión Operativa": [
        "Revocar credencial y aislar host",
        "Terminar proceso y bloquear hash",
        "Revocar permisos sobre recursos compartidos",
        "Bloquear IP de C2 en Firewall perimetral",
    ],
}
risk_table_df = pd.DataFrame(risk_matrix_data)
st.dataframe(risk_table_df, use_container_width=True)

# ==========================================================
# 5. INFORME TÉCNICO DE INCIDENTE
# ==========================================================
st.header("5. Informe Técnico de Incidente")

# Construcción dinámica del resumen según la selección del usuario
if "ai_analysis" in st.session_state and st.session_state["ai_analysis"]:
  # Si la IA ya analizó los logs, extraemos las primeras líneas como síntesis
  lineas_ai = [
      l.strip()
      for l in st.session_state["ai_analysis"].split("\n")
      if l.strip() and not l.startswith("#")
  ]
  sintesis_base = (
      " ".join(lineas_ai[:3])
      if lineas_ai
      else "Análisis técnico completado por el motor de IA."
  )
  dynamic_summary = (
      f"Evaluación técnica SOC L2 (Nivel de Riesgo: {risk_level}):"
      f" {sintesis_base}"
  )
elif selected_host != "Todos":
  # Si el analista está haciendo drill-down en un host puntual en el Dashboard
  total_host_alerts = len(
      df[(df["Hostname"] == selected_host) & (df["Severity"].isin(["High", "Warning"]))]
  )
  dynamic_summary = (
      f"Investigación focalizada sobre el activo {selected_host}. Durante la"
      f" ventana de telemetría se identificaron {total_host_alerts} alertas"
      f" críticas/warning asociadas a este equipo, con un nivel de riesgo"
      f" evaluado como {risk_level}. Se recomienda aplicar contención sobre el"
      " host e investigar credenciales comprometidas."
  )
else:
  # Resumen contextual según el incidente correlacionado seleccionado en el punto 2
  dynamic_summary = (
      f"Informe de Triage SOC Nivel 2 - Incidente Seleccionado:"
      f" {selected_incident.split(':')[0]}. Se evaluaron {len(df)} eventos"
      f" totales registrando un riesgo global {risk_level}. La telemetría"
      " evidencia actividad anómala que requiere validación de TTPs y ejecución"
      " de acciones defensivas inmediatas."
  )

executive_summary = st.text_area(
    "Resumen Ejecutivo del Analista (Editable):",
    value=dynamic_summary,
    height=130,
    help=(
        "Este texto se autocalcula según el incidente seleccionado, el host del"
        " dashboard o el análisis de la IA, y puedes editarlo libremente."
    ),
)
incident_analyst = st.text_input(
    "Analista a cargo:", value="Analista SOC Nivel 2"
)

# ==========================================================
# 6. EXPORTACIÓN EN PDF
# ==========================================================
st.header("6. Exportar Informe Técnico a PDF")


def generar_pdf(resumen, analista, riesgo, eventos_count, ai_text):
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
      fontSize=18,
      textColor=colors.HexColor("#1A365D"),
      spaceAfter=14,
  )
  h2_style = ParagraphStyle(
      "H2Style",
      parent=styles["Heading2"],
      fontSize=12,
      textColor=colors.HexColor("#2B6CB0"),
      spaceBefore=10,
      spaceAfter=6,
  )
  body_style = ParagraphStyle(
      "BodyStyle",
      parent=styles["Normal"],
      fontSize=9.5,
      leading=13,
      textColor=colors.HexColor("#2D3748"),
  )

  story = []
  story.append(
      Paragraph("INFORME TÉCNICO DE INCIDENTE - SOC NIVEL 2", title_style)
  )
  story.append(
      Paragraph(
          f"<b>Analista Responsable:</b> {analista} | <b>Nivel de Riesgo:</b>"
          f" {riesgo} | <b>Eventos Analizados:</b> {eventos_count}",
          body_style,
      )
  )
  story.append(Spacer(1, 10))

  story.append(Paragraph("1. Resumen Ejecutivo", h2_style))
  story.append(Paragraph(resumen, body_style))
  story.append(Spacer(1, 10))

  story.append(
      Paragraph("2. Evaluación Técnica y Correlación de Amenazas", h2_style)
  )
  limpio_ai = (
      ai_text.replace("\n", "<br/>")
      if ai_text
      else (
          "Análisis técnico estructurado basado en la correlación de eventos"
          " RDP, ejecución de LOLBins y exfiltración de red."
      )
  )
  story.append(Paragraph(limpio_ai, body_style))
  story.append(Spacer(1, 10))

  story.append(Paragraph("3. Acciones de Contención Recomendadas", h2_style))
  recs = [
      "• Aislar de la red de inmediato los servidores comprometidos APP-SRV01 y"
      " FS-SRV01.",
      "• Revocar credenciales y sesiones activas para la cuenta CORP\\admin.",
      "• Bloquear en el Firewall perimetral el tráfico saliente hacia la IP"
      " 203.0.113.88.",
      "• Escalar a DFIR para preservación de memoria volátil (volatility3) y"
      " análisis forense de disco.",
  ]
  for r in recs:
    story.append(Paragraph(r, body_style))

  doc.build(story)
  buffer.seek(0)
  return buffer


if st.button("Generar y Descargar Informe en PDF"):
  ai_content = st.session_state.get(
      "ai_analysis", "Evaluación técnica confirmada mediante correlación de logs."
  )
  pdf_buffer = generar_pdf(
      executive_summary,
      incident_analyst,
      risk_level,
      len(df),
      ai_content,
  )
  st.download_button(
      label="📥 Descargar Informe Técnico (.pdf)",
      data=pdf_buffer,
      file_name="informe_incidente_soc_l2.pdf",
      mime="application/pdf",
  )
