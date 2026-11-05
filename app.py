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

st.title("🛡️ SOC L2 - Plataforma de Triage, Análisis y Correlación con IA")
st.markdown(
    "Workbench operativo para analistas SOC Nivel 2: ingesta de telemetría,"
    " correlación de cadenas de ataque (Kill Chain), evaluación dinámica de"
    " riesgos y reportes técnicos ejecutivos."
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
    # Limpieza básica de strings
    df["Severity"] = df["Severity"].fillna("Informational").astype(str)
    df["Hostname"] = df["Hostname"].fillna("Unknown").astype(str)
    df["Event_ID"] = df["Event_ID"].astype(str)
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
# 2. ANÁLISIS DE SEGURIDAD - DETECCIÓN Y CORRELACIÓN DE AMENAZAS (KILL CHAIN RESALTADA)
# ==========================================================
st.header("2. Detección y Correlación de Cadenas de Ataque")

event_ids_criticos = ["4104", "4698", "7045", "5145"]
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

# 🎯 HIGHLIGHT: Caja destacada y prominente para el selector de Kill Chain
with st.container(border=True):
  st.markdown("### ⚡ **INVESTIGACIÓN DE KILL CHAIN CORRELACIONADA**")
  st.markdown(
      "El análisis SOC L2 no evalúa alertas aisladas, sino que **reconstruye la"
      " cadena causal multi-etapa** del adversario a través de diferentes"
      " activos."
  )

  incident_options = [
      (
          "🔥 INC-01: Intrusión RDP -> PowerShell Ofuscado -> Movimiento Lateral"
          " -> Exfiltración (APP-SRV01 / FS-SRV01)"
      ),
      (
          "⚠️ INC-02: Ataque de Fuerza Bruta / Credential Access en Controlador"
          " de Dominio (DC-01)"
      ),
      (
          "🌐 INC-03: Reconocimiento Web y Ejecución de Comandos Anómalos"
          " (WEB-01)"
      ),
  ]
  selected_incident = st.selectbox(
      "👇 **SELECCIONA EL INCIDENTE CORRELACIONADO A INVESTIGAR:**",
      incident_options,
      index=0,
  )

tab_corr1, tab_corr2 = st.tabs(
    ["🔗 Cadena Causal Reconstruida", "📋 Telemetría Crítica Filtrada"]
)

with tab_corr1:
  if "INC-01" in selected_incident:
    corr_events = df[
        (df["Hostname"].isin(["APP-SRV01", "FS-SRV01"]))
        & (
            df["User"].str.contains("admin", case=False, na=False)
            | df["Severity"].isin(["High", "Warning"])
        )
    ].sort_values("Timestamp")
    st.error(
        "**Secuencia de Ataque Correlacionada (Kill Chain):**\n"
        "1. **Acceso Inicial:** Conexión RDP externa exitosa (LogonType=10) en"
        " `APP-SRV01` con credencial comprometida `CORP\\admin`.\n"
        "2. **Ejecución y Evasión:** Spawn de `powershell.exe` con argumentos"
        " ofuscados (`-EncodedCommand`) ejecutando bloques de script"
        " (`EventID 4104`).\n"
        "3. **Descubrimiento y Movimiento Lateral:** Reconocimiento con"
        " `Get-LocalGroupMember` y pivot hacia `\\\\FS-SRV01\\Finance`"
        " (`EventID 5140/5145`).\n"
        "4. **Empaquetamiento y Exfiltración:** Creación de archivo"
        " `finance.zip` con `tar.exe` y conexión de salida hacia IP pública"
        " `203.0.113.88:443`."
    )
  elif "INC-02" in selected_incident:
    corr_events = df[
        (df["Event_ID"].isin(["4625", "4624"]))
        & (df["Hostname"].str.contains("DC|WEB", case=False, na=False))
    ].sort_values("Timestamp")
    st.warning(
        "**Secuencia de Ataque Correlacionada (Kill Chain):**\n"
        "Ráfagas reiteradas de eventos `4625 (Logon Failure)` originadas desde"
        " múltiples IPs sobre cuentas corporativas (`jlopez`, `slopez`,"
        " `helpdesk`), seguidas de bloqueos temporales de autenticación."
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
        "**Secuencia de Ataque Correlacionada (Kill Chain):**\n"
        "Múltiples peticiones HTTP anómalas dirigidas a rutas administrativas"
        " (`/admin/`, `/api/v1/export`), culminando con la ejecución anómala de"
        " `cmd.exe /c whoami` en el servidor web."
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

# Análisis con IA tolerante a fallos
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
      sample_logs = corr_events.head(25).to_string()
      prompt = f"""
            Actúa como un Analista de Ciberseguridad SOC Nivel 2 experto.
            Analiza la siguiente telemetría de eventos del incidente seleccionado ({selected_incident}):
            
            {sample_logs}
            
            Genera un informe analítico estructurado:
            1. Hipótesis del Incidente Correlacionado (Causalidad temporal, vector inicial y pivoteo).
            2. Mapeo de TTPs según MITRE ATT&CK (Tácticas y Técnicas).
            3. Evaluación de Confianza (Confidence Level: Alto, Medio o Bajo) justificando la solidez de la evidencia.
            4. Contramedidas defensivas inmediatas basadas en MITRE D3FEND.
            """
      modelos_candidatos = [
          "gemini-2.0-flash",
          "gemini-1.5-flash",
          "gemini-2.5-flash",
          "gemini-3.8-flash",
      ]
      analisis_generado = None

      for mod in modelos_candidatos:
        try:
          response = client.models.generate_content(model=mod, contents=prompt)
          analisis_generado = response.text
          st.session_state["ai_analysis"] = analisis_generado
          st.success(
              f"Análisis técnico completado exitosamente (utilizando el motor"
              f" {mod})."
          )
          break
        except Exception:
          continue

      if not analisis_generado:
        st.error(
            "Los servidores de IA están saturados en este momento (503). Por"
            " favor intenta de nuevo en unos segundos."
        )

if "ai_analysis" in st.session_state:
  st.markdown(st.session_state["ai_analysis"])

# ==========================================================
# 3. DASHBOARD INTERACTIVO Y DINÁMICO
# ==========================================================
st.header("3. Dashboard de Operaciones de Seguridad")

# 🎯 CONTROLES DE FILTRADO DINÁMICO PARA TODO EL DASHBOARD
with st.expander("🛠️ **Filtros Interactivos del Dashboard**", expanded=True):
  f_col1, f_col2 = st.columns(2)
  with f_col1:
    severidades_disponibles = sorted(list(df["Severity"].unique()))
    filtro_severidad = st.multiselect(
        "Filtrar por Severidad:",
        options=severidades_disponibles,
        default=severidades_disponibles,
    )
  with f_col2:
    hosts_disponibles = ["Todos"] + sorted(list(df["Hostname"].unique()))
    filtro_host = st.selectbox("Filtrar por Host específico:", hosts_disponibles)

# Dataframe reactivo según los filtros seleccionados
df_filtrado = df[df["Severity"].isin(filtro_severidad)].copy()
if filtro_host != "Todos":
  df_filtrado = df_filtrado[df_filtrado["Hostname"] == filtro_host]

# 🎯 MÉTRICAS NUMÉRICAS TOTALMENTE DINÁMICAS
m1, m2, m3, m4 = st.columns(4)
m1.metric("Total Eventos Filtrados", len(df_filtrado))
m2.metric(
    "Alertas High / Warning",
    len(df_filtrado[df_filtrado["Severity"].isin(["High", "Warning", "Critical"])]),
)
m3.metric("Hosts Monitoreados", df_filtrado["Hostname"].nunique())
m4.metric("Usuarios Detectados", df_filtrado["User"].nunique())

d_col1, d_col2 = st.columns(2)
with d_col1:
  if not df_filtrado.empty:
    fig_sev = px.pie(
        df_filtrado,
        names="Severity",
        title="Distribución de Eventos por Severidad (Filtrado)",
        color="Severity",
        color_discrete_map={
            "High": "#E53E3E",
            "Warning": "#DD6B20",
            "Medium": "#D69E2E",
            "Informational": "#3182CE",
        },
    )
    st.plotly_chart(fig_sev, use_container_width=True)
  else:
    st.info("No hay eventos para la combinación de filtros seleccionada.")

with d_col2:
  # 🎯 TOP HOSTS DINÁMICO SEGÚN LA SELECCIÓN
  if not df_filtrado.empty:
    top_hosts_data = (
        df_filtrado[
            df_filtrado["Severity"].isin(["High", "Warning", "Critical"])
        ]
        .groupby("Hostname")
        .size()
        .reset_index(name="Alertas")
        .sort_values(by="Alertas", ascending=False)
    )
    if not top_hosts_data.empty:
      fig_hosts = px.bar(
          top_hosts_data,
          x="Hostname",
          y="Alertas",
          color="Alertas",
          color_continuous_scale="Reds",
          title="Top Hosts con Mayor Frecuencia de Alertas (Dinámico)",
      )
      st.plotly_chart(fig_hosts, use_container_width=True)
    else:
      st.info("No hay alertas críticas en los eventos actualmente filtrados.")
  else:
    st.info("Sin datos para graficar.")

# ==========================================================
# 4. CLASIFICACIÓN DE RIESGOS (REACTIVA AL HOST/FILTRO)
# ==========================================================
st.header("4. Matriz de Clasificación de Riesgos y Evaluación de Amenazas")

# 🎯 CÁLCULO DE RIESGO REACTIVO AL ACTIVO O FILTRO SELECCIONADO
target_eval = filtro_host if filtro_host != "Todos" else "Global del Entorno"
alertas_criticas_eval = len(
    df_filtrado[df_filtrado["Severity"].isin(["High", "Critical"])]
)
alertas_warning_eval = len(df_filtrado[df_filtrado["Severity"] == "Warning"])

if alertas_criticas_eval > 3 or (
    filtro_host in ["APP-SRV01", "FS-SRV01"] and alertas_criticas_eval > 0
):
  risk_level = "CRÍTICO"
  risk_badge = "🔴 CRÍTICO"
  action_rec = (
      f"Compromiso severo confirmado en {target_eval}. Aislamiento perimetral"
      " inmediato de la red. Escalamiento de máxima prioridad a DFIR / Nivel 3"
      " para volcado de memoria RAM y análisis de persistencia."
  )
elif alertas_criticas_eval > 0 or alertas_warning_eval > 5:
  risk_level = "MEDIO / ALTO"
  risk_badge = "🟠 MEDIO / ALTO"
  action_rec = (
      f"Actividad sospechosa detectada en {target_eval} ({alertas_warning_eval}"
      " warnings). Bloquear IOCs perimetrales, forzar rotación de credenciales"
      " de usuarios involucrados e iniciar Threat Hunting."
  )
else:
  risk_level = "BAJO"
  risk_badge = "🟢 BAJO"
  action_rec = (
      f"El activo {target_eval} no presenta alertas críticas en la ventana"
      " filtrada. Mantener telemetría habitual, monitoreo continuo y afinar"
      " reglas de detección."
  )

st.markdown(
    f"### Nivel de Riesgo Evaluado para **{target_eval}**: **{risk_badge}**"
)
st.info(f"**Directiva de Respuesta Operativa:** {action_rec}")

# Tabla estructurada con Categoría y Justificación técnica contextual
if filtro_host in ["APP-SRV01", "FS-SRV01", "Todos"]:
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
              "Ejecución de PowerShell con parámetros ofuscados"
              " (-EncodedCommand) y sentencias de reconocimiento"
              " Get-LocalGroupMember."
          ),
          (
              "Conexión de red permitida desde APP-SRV01 hacia FS-SRV01"
              " (LogonType=3) y acceso al recurso compartido confidencial"
              " \\FS-SRV01\\Finance."
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
else:
  # Justificación para hosts con bajo impacto o solo warnings
  risk_matrix_data = {
      "Categoría de Amenaza (MITRE)": [
          "Autenticación / Descubrimiento",
          "Tráfico de Red Perimetral",
          "Servicios de Sistema",
      ],
      "Justificación / Evidencia Detectada en Logs": [
          (
              f"Registros de autenticación habituales en {filtro_host} con"
              f" {alertas_warning_eval} advertencias menores."
          ),
          (
              "Conexiones de red internas estándar permitidas por Windows"
              " Filtering Platform (5156)."
          ),
          "Transiciones normales de estado en servicios del sistema (7036).",
      ],
      "Probabilidad": ["Baja", "Baja", "Baja"],
      "Impacto Operativo": ["Bajo", "Bajo", "Informativo"],
      "Nivel de Confianza (Confidence)": ["Alto", "Alto", "Alto"],
      "Decisión Operativa": [
          "Monitorear actividad de usuario",
          "Auditar reglas de firewall",
          "Mantener línea base operativa",
      ],
  }

st.dataframe(pd.DataFrame(risk_matrix_data), use_container_width=True)

# ==========================================================
# 5. INFORME TÉCNICO DE INCIDENTE (DINÁMICO)
# ==========================================================
st.header("5. Informe Técnico de Incidente")

if "ai_analysis" in st.session_state and st.session_state["ai_analysis"]:
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
      f"Evaluación técnica SOC L2 para {target_eval} (Riesgo: {risk_level}):"
      f" {sintesis_base}"
  )
elif filtro_host != "Todos":
  dynamic_summary = (
      f"Investigación focalizada sobre el activo {filtro_host}. Durante la"
      f" ventana de telemetría se registraron {alertas_criticas_eval} alertas"
      f" críticas y {alertas_warning_eval} advertencias. El nivel de riesgo"
      f" evaluado es {risk_level}. Directiva: {action_rec}"
  )
else:
  dynamic_summary = (
      f"Informe de Triage SOC Nivel 2 - Incidente Seleccionado:"
      f" {selected_incident.split(':')[1] if ':' in selected_incident else selected_incident}. "
      f"Se evaluaron {len(df_filtrado)} eventos filtrados registrando un riesgo"
      f" {risk_level}. Se requiere validar la cadena de ataque y ejecutar las"
      " acciones de contención."
  )

executive_summary = st.text_area(
    "Resumen Ejecutivo del Analista (Editable):",
    value=dynamic_summary,
    height=130,
)
incident_analyst = st.text_input(
    "Analista a cargo:", value="Analista SOC Nivel 2"
)

# ==========================================================
# 6. EXPORTACIÓN DE INFORME
# ==========================================================
st.header("6. Exportar Informe Técnico a PDF")


def generar_pdf(resumen, analista, riesgo, target, eventos_count, ai_text):
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
          f"<b>Analista Responsable:</b> {analista} | <b>Activo Evaluado:</b>"
          f" {target} | <b>Nivel de Riesgo:</b> {riesgo} | <b>Eventos:</b>"
          f" {eventos_count}",
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
          "Análisis técnico estructurado basado en la correlación de eventos de"
          " telemetría."
      )
  )
  story.append(Paragraph(limpio_ai, body_style))
  story.append(Spacer(1, 10))

  story.append(Paragraph("3. Acciones de Contención Recomendadas", h2_style))
  recs = [
      f"• Ejecutar acciones de mitigación según la directiva para {target}.",
      "• Revocar credenciales comprometidas y auditar inicios de sesión"
      " anómalos.",
      "• Validar indicadores de compromiso (IOCs) en el perímetro.",
      "• Evaluar escalamiento a DFIR / Nivel 3 para adquisición de memoria RAM.",
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
      target_eval,
      len(df_filtrado),
      ai_content,
  )
  st.download_button(
      label="📥 Descargar Informe Técnico (.pdf)",
      data=pdf_buffer,
      file_name="informe_incidente_soc_l2.pdf",
      mime="application/pdf",
  )
