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

st.title("🛡️ SOC L2 - Plataforma de Triage, Análisis y Reportes con IA")
st.markdown(
    "Herramienta integral para analistas SOC Nivel 2: ingesta de telemetría, detección de TTPs, evaluación de riesgos y generación técnica de incidentes."
)

# Inicialización de la API de IA (compatible con Secrets de Streamlit o variables de entorno)
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
    # Soporta delimitador ';' típico de los datasets de Windows/SOC
    df = pd.read_csv(uploaded_file, sep=";")
    if "Event_ID" not in df.columns and ";" not in uploaded_file.name:
      uploaded_file.seek(0)
      df = pd.read_csv(uploaded_file, sep=",")
    st.success(
        f"Archivo cargado correctamente: {len(df)} eventos de seguridad"
        " registrados."
    )
  except Exception as e:
    st.error(f"Error al leer el archivo: {e}")
    st.stop()
else:
  st.info(
      "Por favor sube tu archivo CSV de logs para activar el análisis y el"
      " dashboard."
  )
  st.stop()

# ==========================================================
# 2. ANÁLISIS DE SEGURIDAD (Triage SOC Nivel 2)
# ==========================================================
st.header("2. Detección y Análisis de Amenazas")

# Filtrar eventos sospechosos / críticos
suspicious_events = df[
    df["Severity"].isin(["High", "Warning", "Critical"])
    | df["Process_CommandLine"].str.contains(
        "powershell|cmd|vssadmin|net |whoami|-enc|bypass",
        case=False,
        na=False,
    )
    | df["Event_ID"].isin([4625, 4698, 7045, 1102])
]

col_s1, col_s2 = st.columns([1, 1])
with col_s1:
  st.subheader("Eventos Sospechosos Identificados")
  st.dataframe(
      suspicious_events[[
          "Timestamp",
          "Hostname",
          "Event_ID",
          "User",
          "Severity",
          "Process_CommandLine",
      ]].head(15),
      use_container_width=True,
  )

with col_s2:
  st.subheader("Evaluación Asistida por IA")
  if st.button("Ejecutar Análisis Técnico con IA"):
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
        # Preparar muestra representativa de eventos para el prompt
        sample_logs = suspicious_events.head(25).to_string()
        prompt = f"""
                Actúa como un Analista de Ciberseguridad SOC Nivel 2 experto.
                Analiza la siguiente telemetría de eventos sospechosos extraída de los logs:
                
                {sample_logs}
                
                Genera un análisis técnico estructurado con:
                1. Hipótesis del Incidente (Vector inicial probable, movimiento lateral, persistencia).
                2. TTPs identificados mapeados con MITRE ATT&CK (técnicas y tácticas).
                3. Evaluación de Confianza (Confidence: Alto, Medio o Bajo) fundamentada en la evidencia.
                4. Contramedidas defensivas inmediatas basadas en MITRE D3FEND.
                """
        try:
          response = client.models.generate_content(
              model="gemini-2.5-flash", contents=prompt
          )
          st.session_state["ai_analysis"] = response.text
          st.success("Análisis completado exitosamente.")
        except Exception as err:
          st.error(f"Error al consultar la IA: {err}")

  if "ai_analysis" in st.session_state:
    st.markdown(st.session_state["ai_analysis"])

# ==========================================================
# 3. DASHBOARD INTERACTIVO
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
      df, names="Severity", title="Distribución de Eventos por Severidad"
  )
  st.plotly_chart(fig_sev, use_container_width=True)

with d_col2:
  top_hosts = (
      df[df["Severity"].isin(["High", "Warning"])]
      .groupby("Hostname")
      .size()
      .reset_index(name="Alertas")
  )
  fig_hosts = px.bar(
      top_hosts,
      x="Hostname",
      y="Alertas",
      color="Alertas",
      title="Top Hosts con Mayor Frecuencia de Alertas",
  )
  st.plotly_chart(fig_hosts, use_container_width=True)

# ==========================================================
# 4. CLASIFICACIÓN DE RIESGOS (Matriz SOC L2)
# ==========================================================
st.header("4. Matriz y Clasificación de Riesgos")

num_critical = len(df[df["Severity"].isin(["High", "Critical"])])
if num_critical > 10:
  risk_level = "CRÍTICO"
  risk_color = "red"
  action_rec = "Escalar de inmediato a DFIR / Nivel 3. Aislar hosts afectados."
elif num_critical > 0:
  risk_level = "MEDIO / ALTO"
  risk_color = "orange"
  action_rec = (
      "Bloquear IOCs en Firewall/Proxy y ejecutar Threat Hunting en endpoints."
  )
else:
  risk_level = "BAJO"
  risk_color = "green"
  action_rec = "Mantener monitoreo continuo y afinar reglas de detección."

st.markdown(
    f"### Nivel de Riesgo Global: **:{risk_color}[{risk_level}]**"
)
st.write(f"**Recomendación Operativa:** {action_rec}")

# Tabla de clasificación
risk_data = {
    "Categoría": ["Acceso Inicial", "Ejecución", "Persistencia", "Exfiltración"],
    "Probabilidad": ["Alta", "Media", "Baja", "Media"],
    "Impacto Operativo": ["Alto", "Crítico", "Crítico", "Crítico"],
    "Confidence": ["Alto", "Alto", "Medio", "Medio"],
    "Decisión": ["Bloquear IP", "Matar Proceso", "Auditar Tareas", "Bloquear C2"],
}
st.table(pd.DataFrame(risk_data))

# ==========================================================
# 5. INFORME TÉCNICO DE INCIDENTE
# ==========================================================
st.header("5. Informe Técnico de Incidente")

default_summary = (
    "Durante el análisis de telemetría se detectó actividad anómala persistente"
    " en servidores clave, con ejecuciones sospechosas en línea de comandos y"
    " fallas reiteradas de autenticación (fuerza bruta). Se aplicó la"
    " metodología SOC Nivel 2 correlacionando eventos e identificando TTPs del"
    " adversario."
)

executive_summary = st.text_area(
    "Resumen Ejecutivo del Analista:", value=default_summary, height=120
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
      fontSize=13,
      textColor=colors.HexColor("#2B6CB0"),
      spaceBefore=10,
      spaceAfter=6,
  )
  body_style = ParagraphStyle(
      "BodyStyle",
      parent=styles["Normal"],
      fontSize=10,
      leading=14,
      textColor=colors.HexColor("#2D3748"),
  )

  story = []
  story.append(
      Paragraph("INFORME TÉCNICO DE INCIDENTE - SOC NIVEL 2", title_style)
  )
  story.append(
      Paragraph(
          f"<b>Analista:</b> {analista} | <b>Nivel de Riesgo:</b> {riesgo} |"
          f" <b>Eventos Analizados:</b> {eventos_count}",
          body_style,
      )
  )
  story.append(Spacer(1, 12))

  story.append(Paragraph("1. Resumen Ejecutivo", h2_style))
  story.append(Paragraph(resumen, body_style))
  story.append(Spacer(1, 10))

  story.append(Paragraph("2. Evaluación Técnica y Análisis de IA", h2_style))
  limpio_ai = (
      ai_text.replace("\n", "<br/>")
      if ai_text
      else (
          "No se ejecutó el análisis de IA previo a la generación del informe."
      )
  )
  story.append(Paragraph(limpio_ai, body_style))
  story.append(Spacer(1, 10))

  story.append(Paragraph("3. Recomendaciones Operativas", h2_style))
  recs = [
      "• Aislar de la red los hosts comprometidos para análisis forense.",
      "• Revocar credenciales y forzar rotación de contraseñas de cuentas"
      " afectadas.",
      "• Incorporar IOCs identificados a las listas de bloqueo perimetrales.",
      "• Escalar a DFIR para preservación de memoria volátil y adquisición de"
      " disco.",
  ]
  for r in recs:
    story.append(Paragraph(r, body_style))

  doc.build(story)
  buffer.seek(0)
  return buffer


if st.button("Generar y Descargar Informe en PDF"):
  ai_content = st.session_state.get(
      "ai_analysis", "Análisis manual basado en reglas heurísticas."
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
