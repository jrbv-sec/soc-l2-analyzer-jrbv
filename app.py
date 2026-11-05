import io
import os
import time
import pandas as pd
import plotly.express as px
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
import streamlit as st

# Importación segura del SDK de IA
try:
  from google import genai
except ImportError:
  genai = None

# ==========================================================
# CONFIGURACIÓN Y TEMA VISUAL CLARO (ALTO CONTRASTE)
# ==========================================================
st.set_page_config(
    page_title="SOC L2 Defense Workbench",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
<style>
    .stApp {
        background-color: #F8FAFC;
        color: #0F172A;
    }
    .main-title {
        font-size: 2.2rem;
        font-weight: 800;
        color: #0F172A;
        margin-bottom: 0.2rem;
    }
    .sub-title {
        font-size: 1.05rem;
        color: #475569;
        margin-bottom: 1.5rem;
    }
    div[data-testid="stMetric"] {
        background-color: #FFFFFF;
        border: 1px solid #CBD5E1;
        padding: 16px;
        border-radius: 10px;
        box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
    }
    div[data-testid="stMetricLabel"] {
        color: #475569 !important;
        font-weight: 700;
    }
    div[data-testid="stMetricValue"] {
        color: #1E40AF !important;
        font-family: monospace;
        font-size: 1.9rem;
    }
    div[data-testid="stVerticalBlock"] > div[data-testid="stContainer"] {
        background-color: #FFFFFF;
        border: 1px solid #E2E8F0;
        border-radius: 10px;
        padding: 18px;
        box-shadow: 0 1px 3px rgba(0,0,0,0.05);
    }
    .badge-critical {
        background-color: #DC2626;
        color: #FFFFFF;
        padding: 4px 10px;
        border-radius: 6px;
        font-weight: bold;
        font-size: 0.85rem;
    }
    .badge-high {
        background-color: #EA580C;
        color: #FFFFFF;
        padding: 4px 10px;
        border-radius: 6px;
        font-weight: bold;
        font-size: 0.85rem;
    }
    .badge-medium {
        background-color: #D97706;
        color: #FFFFFF;
        padding: 4px 10px;
        border-radius: 6px;
        font-weight: bold;
        font-size: 0.85rem;
    }
    .badge-all {
        background-color: #4F46E5;
        color: #FFFFFF;
        padding: 4px 10px;
        border-radius: 6px;
        font-weight: bold;
        font-size: 0.85rem;
    }
    /* Estilo para resaltar fila coincidente en la matriz */
    .highlight-card {
        background-color: #EFF6FF !important;
        border: 2px solid #2563EB !important;
        border-radius: 8px;
        padding: 12px;
        margin-bottom: 8px;
    }
    .normal-card {
        background-color: #F8FAFC !important;
        border: 1px solid #E2E8F0 !important;
        border-radius: 8px;
        padding: 12px;
        margin-bottom: 8px;
        opacity: 0.75;
    }
</style>
""",
    unsafe_allow_html=True,
)

st.markdown(
    "<div class='main-title'>🛡️ SOC L2 DEFENSE WORKBENCH</div>",
    unsafe_allow_html=True,
)
st.markdown(
    "<div class='sub-title'>Plataforma Unificada de Operaciones de Seguridad:"
    " Triage Heurístico, Correlación de Kill Chain y Análisis con IA.</div>",
    unsafe_allow_html=True,
)

# Inicialización limpia de la API de IA
api_key = st.secrets.get("GEMINI_API_KEY", os.environ.get("GEMINI_API_KEY", ""))
client = None
if api_key and genai is not None:
  api_key = str(api_key).strip().strip('"').strip("'")
  os.environ["GEMINI_API_KEY"] = api_key
  try:
    client = genai.Client(api_key=api_key)
  except Exception as e:
    st.sidebar.warning(f"Error cliente IA: {e}")

# Sidebar Operativo
with st.sidebar:
  st.markdown(
      "<div style='text-align: center; font-size: 2.8rem; margin-bottom:"
      " 0.3rem;'>🛡️</div>",
      unsafe_allow_html=True,
  )
  st.markdown(
      "<h3 style='text-align: center; color: #1E40AF; margin-top: 0;'>Security"
      " Operations</h3>",
      unsafe_allow_html=True,
  )
  if client:
    st.success("🟢 Motor de IA: Conectado")
  else:
    st.error("🔴 Motor de IA: Clave ausente en Secrets")
  st.markdown("---")
  st.markdown("**Nivel Operativo:** Analista SOC L2")
  st.markdown("**Marcos Técnicos:**")
  st.markdown("• MITRE ATT&CK®")
  st.markdown("• MITRE D3FEND™")
  st.markdown("---")
  st.caption("Bootcamp de Ciberseguridad Defensiva")

# ==========================================================
# 1. CARGA DE ARCHIVOS
# ==========================================================
st.markdown("### 📥 1. Ingesta de Telemetría (Security Event Logs)")
uploaded_file = st.file_uploader(
    "Cargar dataset consolidado de seguridad (.CSV)",
    type=["csv", "txt", "log"],
    help="Admite archivos delimitados por ';' o ','",
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
    df["Event_Description"] = df["Event_Description"].fillna("").astype(str)
    st.success(
        f"✅ Telemetría cargada con éxito: **{len(df):,} eventos** registrados."
    )
  except Exception as e:
    st.error(f"Error al procesar el archivo: {e}")
    st.stop()
else:
  st.info("💡 Sube tu archivo CSV de logs para activar el análisis completo.")
  st.stop()

# ==========================================================
# CLASIFICACIÓN DE VECTORES ANALÍTICOS (6 VECTORES)
# ==========================================================


def clasificar_vector(row):
  cmd = row["Process_CommandLine"].lower()
  desc = row["Event_Description"].lower()
  eid = row["Event_ID"]

  if eid == "4625" or "failed to log on" in desc:
    return "Fuerza Bruta & Credenciales"
  if "logontype=10" in desc or (
      eid == "4624"
      and (
          "203.0.113" in row["Source_IP"]
          or row["User"] in ["CORP\\admin", "CORP\\backupsvc"]
      )
  ):
    return "Inicios de Sesión Sospechosos"
  if (
      eid == "4672"
      or "special privileges" in desc
      or "get-localgroupmember" in cmd
  ):
    return "Escalamiento de Privilegios"
  if any(
      k in cmd
      for k in [
          "powershell",
          "-encodedcommand",
          "vssadmin",
          "whoami",
          "cmd.exe /c",
      ]
  ):
    return "Comandos y Procesos (LOLBins)"
  if (
      eid in ["5140", "5145"]
      or "logontype=3" in desc
      or "\\\\fs-srv01" in row["Destination"].lower()
  ):
    return "Movimiento Lateral"
  if (
      "tar.exe" in cmd
      or "203.0.113.88" in row["Destination"]
      or any(k in cmd for k in ["/admin/", "/api/v1/export"])
  ):
    return "Otras Anomalías / Exfiltración"

  return "Actividad Normal / Línea Base"


df["Vector_Analitico"] = df.apply(clasificar_vector, axis=1)

# ==========================================================
# 2. SELECTOR DE INCIDENTES Y CORRELACIÓN DE KILL CHAIN
# ==========================================================
st.markdown("---")
st.markdown("### 🎯 2. Selector Maestro de Incidentes Correlacionados")

catalog_incidentes = {
    "INC-ALL": {
        "title": (
            "Todos los Incidentes Consolidados (Vista Global del Entorno)"
        ),
        "badge": "VISTA GLOBAL",
        "hosts": sorted(list(df["Hostname"].dropna().unique())),
        "matched_vectors": [
            "Fuerza Bruta & Credenciales",
            "Inicios de Sesión Sospechosos",
            "Escalamiento de Privilegios",
            "Comandos y Procesos (LOLBins)",
            "Movimiento Lateral",
            "Otras Anomalías / Exfiltración",
        ],
        "kill_chain": (
            "Visión consolidada multicapa: ataque distribuido que abarca acceso"
            " inicial RDP y pulverización de contraseñas, ejecución de scripts"
            " ofuscados, movimiento lateral hacia servidores de archivos,"
            " intento de ransomware y preparación de exfiltración de datos."
        ),
        "filter": lambda d: d[
            d["Severity"].isin(["High", "Warning", "Critical"])
            | d["Vector_Analitico"].ne("Actividad Normal / Línea Base")
        ],
        "risk_level": "CRÍTICO",
        "mitre_technique": (
            "T1078, T1110.003, T1059.001, T1021.002, T1486, T1490, T1048"
        ),
        "action": (
            "Activar el Comité de Crisis de Ciberseguridad. Ejecutar contención"
            " coordinada perimetral, aislar hosts afectados (APP-SRV01,"
            " FS-SRV01, DC-01, WS-023, WEB-01) y activar investigación forense"
            " integral."
        ),
    },
    "INC-01": {
        "title": (
            "INC-01: Intrusión RDP, Ejecución de LOLBins y Exfiltración de"
            " Finanzas"
        ),
        "badge": "CRÍTICO",
        "hosts": ["APP-SRV01", "FS-SRV01"],
        "matched_vectors": [
            "Inicios de Sesión Sospechosos",
            "Comandos y Procesos (LOLBins)",
            "Movimiento Lateral",
            "Otras Anomalías / Exfiltración",
        ],
        "kill_chain": (
            "1. Acceso RDP exitoso (LogonType=10) en APP-SRV01 -> 2. Invocación"
            " de PowerShell ofuscado (-EncodedCommand) -> 3. Movimiento lateral"
            " hacia FS-SRV01 accediendo a Budget2027.xlsx -> 4. Empaquetamiento"
            " con tar.exe -> 5. Conexión externa de salida a IP"
            " 203.0.113.88:443."
        ),
        "filter": lambda d: d[
            (d["Hostname"].isin(["APP-SRV01", "FS-SRV01"]))
            & (
                d["User"].str.contains("admin", case=False, na=False)
                | d["Severity"].isin(["High", "Warning"])
                | d["Process_CommandLine"].str.contains(
                    "powershell|tar|Get-LocalGroupMember", case=False, na=False
                )
                | d["Destination"].str.contains("Finance", case=False, na=False)
            )
        ],
        "risk_level": "CRÍTICO",
        "mitre_technique": (
            "T1078 (Valid Accounts), T1059.001 (PowerShell), T1021.002 (SMB"
            " Shares), T1048 (Exfiltration Over Alternative Protocol)"
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
        "hosts": ["DC-01", "DC01"],
        "matched_vectors": ["Fuerza Bruta & Credenciales"],
        "kill_chain": (
            "Ráfaga continua y secuencial de eventos EventID 4625 (Logon"
            " Failure) originada desde múltiples IPs internas (10.10.1.x,"
            " 10.10.2.x, 10.10.3.x) intentando autenticar sistemáticamente"
            " contra cuentas corporativas clave en DC-01."
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
        "action": (
            "Bloquear temporalmente las cuentas de usuario afectadas, forzar"
            " cambio de credenciales y aislar estaciones de origen para"
            " análisis de malware."
        ),
    },
    "INC-03": {
        "title": "INC-03: Fuzzing Web y Ejecución de Comandos Anómalos",
        "badge": "MEDIO / ALTO",
        "hosts": ["WEB-01"],
        "matched_vectors": [
            "Comandos y Procesos (LOLBins)",
            "Otras Anomalías / Exfiltración",
        ],
        "kill_chain": (
            "Escaneo masivo de rutas no autorizadas (/admin/, /api/v1/export)"
            " desde IP externa, seguido de ejecución de subproceso de consola"
            " interactiva 'cmd.exe /c whoami' bajo el proceso del servidor web."
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
        "action": (
            "Bloquear IP atacante en WAF/Proxy, terminar procesos cmd.exe"
            " activos en WEB-01 y auditar código de la aplicación web."
        ),
    },
    "INC-04": {
        "title": "INC-04: Actividad de Ransomware y Destrucción de Backups",
        "badge": "CRÍTICO",
        "hosts": ["WS-023", "FS-SRV01"],
        "matched_vectors": [
            "Inicios de Sesión Sospechosos",
            "Comandos y Procesos (LOLBins)",
            "Movimiento Lateral",
            "Otras Anomalías / Exfiltración",
        ],
        "kill_chain": (
            "1. Ejecución de PowerShell codificado en WS-023 -> 2. Acceso"
            " simultáneo y masivo a decenas de archivos en \\\\FS-SRV01\\Finance"
            " -> 3. Ejecución de 'vssadmin.exe delete shadows /all /quiet' para"
            " inhibir la recuperación del sistema."
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
        "action": (
            "Aislar de emergencia WS-023 y el servidor FS-SRV01. Suspender"
            " cuenta CORP\\backupsvc y activar playbooks de mitigación de"
            " Ransomware."
        ),
    },
}

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

# Dataset contextual rector
df_incidente = inc_meta["filter"](df).copy().sort_values("Timestamp")
if df_incidente.empty:
  df_incidente = df[df["Hostname"].isin(inc_meta["hosts"])].copy()

# Cálculo dinámico de IPs, Hosts y Usuarios
ips_atacantes_detectadas = [
    ip
    for ip in df_incidente["Source_IP"].dropna().unique()
    if ip not in ["N/A", "nan", ""]
]
str_ips_atacantes = (
    ", ".join(ips_atacantes_detectadas)
    if ips_atacantes_detectadas
    else "Origen Interno / No identificado"
)

hosts_victimas_detectados = [
    h
    for h in df_incidente["Hostname"].dropna().unique()
    if h not in ["Unknown", "nan", ""]
]
str_hosts_victimas = ", ".join(hosts_victimas_detectados)

usuarios_implicados = [
    u
    for u in df_incidente["User"].dropna().unique()
    if u not in ["SYSTEM", "nan", ""]
]
str_usuarios = ", ".join(usuarios_implicados[:8])

# Tarjeta de resumen visual
with st.container():
  c1, c2 = st.columns([3, 1])
  with c1:
    st.markdown(f"#### 🔎 **{inc_meta['title']}**")
    st.markdown(
        f"**🔴 IPs de Origen / Atacantes Detectadas ({len(ips_atacantes_detectadas)}):**"
        f" `{str_ips_atacantes}`"
    )
    st.markdown(
        f"**🎯 Activos Víctima Comprometidos:** `{str_hosts_victimas}`"
        f" &nbsp;|&nbsp; **Cuentas Involucradas:** `{str_usuarios}`"
    )
    st.markdown(f"**⚡ Kill Chain Reconstruida:** {inc_meta['kill_chain']}")
  with c2:
    st.markdown("**Nivel de Severidad:**")
    if inc_meta["badge"] == "CRÍTICO":
      st.markdown(
          f"<span class='badge-critical'>{inc_meta['badge']}</span>",
          unsafe_allow_html=True,
      )
    elif inc_meta["badge"] == "VISTA GLOBAL":
      st.markdown(
          f"<span class='badge-all'>{inc_meta['badge']}</span>",
          unsafe_allow_html=True,
      )
    else:
      st.markdown(
          f"<span class='badge-high'>{inc_meta['badge']}</span>",
          unsafe_allow_html=True,
      )
    st.caption(f"Total Eventos Correlacionados: {len(df_incidente)}")

# Telemetría Detallada
with st.expander(
    f"📋 Telemetría Crítica Correlacionada ({len(df_incidente)} eventos) - Detalle Completo Atacante vs. Víctima",
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
          "Vector_Analitico",
          "Process_CommandLine",
          "Event_Description",
      ]].rename(
          columns={
              "Source_IP": "IP Origen (Atacante)",
              "Hostname": "Host Víctima",
              "Destination": "Destino / Recurso",
              "Vector_Analitico": "Vector Detectado",
          }
      ),
      use_container_width=True,
  )

# ==========================================================
# EVALUACIÓN ASISTIDA POR IA (GUARDADO EN VARIABLE + POP-UP MODAL)
# ==========================================================
st.markdown("#### 🤖 Evaluación Analítica con Inteligencia Artificial")


# Modal interactivo (Pop-up en pantalla)
@st.dialog(f"Dictamen Técnico SOC L2 - {selected_inc_key}", width="large")
def modal_dictamen_ia(texto_ia, inc_titulo):
  st.markdown(f"### 📋 Evaluación de Ciberseguridad: {inc_titulo}")
  st.markdown("---")
  st.markdown(texto_ia)
  st.markdown("---")
  st.caption(
      "Dictamen generado y estructurado con el motor Gemini API bajo marco"
      " MITRE ATT&CK / D3FEND."
  )


col_btn_ia, col_enlace_ia = st.columns([1, 2])
with col_btn_ia:
  ejecutar_ia = st.button(f"Ejecutar Análisis IA ({selected_inc_key})")

if ejecutar_ia:
  if not client:
    st.error(
        "Clave 'GEMINI_API_KEY' no detectada. Configúrala en Settings > Secrets"
        " en Streamlit Cloud."
    )
  else:
    with st.spinner(f"Consultando a Gemini para {selected_inc_key}..."):
      cols_forenses = [
          "Timestamp",
          "Event_ID",
          "Hostname",
          "User",
          "Source_IP",
          "Destination",
          "Process_CommandLine",
      ]
      muestra_logs = (
          df_incidente[cols_forenses].head(12).to_csv(index=False, sep="|")
      )

      prompt = f"""
Eres un Analista SOC L2 Senior. Analiza el siguiente incidente de seguridad: {inc_meta['title']}.
- Actores atacantes (IPs): {str_ips_atacantes}
- Activos víctima: {str_hosts_victimas}
- Cuentas involucradas: {str_usuarios}

Muestra de telemetría forense (CSV delimitado por |):
{muestra_logs}

Genera un dictamen técnico profesional y conciso en Markdown:
1. Hipótesis del Incidente y Vector Inicial (Causalidad temporal específica de {selected_inc_key}).
2. Mapeo de TTPs (MITRE ATT&CK identificados en este conjunto de eventos).
3. Nivel de Confianza (Confidence Level: Alto/Medio/Bajo con justificación basada en los logs).
4. Contramedidas Defensivas Inmediatas (MITRE D3FEND aplicables a {selected_inc_key}).
"""
      modelos_a_probar = [
          "gemini-3.8-flash",
          "gemini-2.0-flash",
          "gemini-1.5-flash",
      ]
      respuesta_obtenida = None
      ultimo_error = ""

      for mod in modelos_a_probar:
        for intento in range(2):
          try:
            res = client.models.generate_content(model=mod, contents=prompt)
            if res and hasattr(res, "text") and res.text:
              respuesta_obtenida = res.text
              # Se guarda estrictamente en una variable de sesión
              st.session_state[f"ai_report_{selected_inc_key}"] = (
                  respuesta_obtenida
              )
              st.session_state[f"ai_engine_{selected_inc_key}"] = mod
              break
          except Exception as e:
            ultimo_error = str(e)
            if "503" in ultimo_error or "high demand" in ultimo_error.lower():
              time.sleep(2)
              continue
            else:
              break
        if respuesta_obtenida:
          break

      if not respuesta_obtenida:
        st.error(f"❌ Error al conectar con la API de Gemini: {ultimo_error}")

# Enlace / Botón para consultar el Pop-Up (Modal) solo si el usuario desea abrirlo
ai_text_actual = st.session_state.get(f"ai_report_{selected_inc_key}", "")
engine_usado = st.session_state.get(f"ai_engine_{selected_inc_key}", "gemini")

with col_enlace_ia:
  if ai_text_actual:
    if st.button(
        f"🔍 Ver Dictamen Técnico de IA en Ventana Modal ({selected_inc_key})"
    ):
      modal_dictamen_ia(ai_text_actual, inc_meta["title"])
  else:
    st.caption(
        "ℹ️ Presiona el botón para procesar la telemetría con IA y generar el"
        " dictamen técnico."
    )

# ==========================================================
# 3. DASHBOARD TOTALMENTE DINÁMICO (FILTROS REACTIVOS)
# ==========================================================
st.markdown("---")
st.markdown(
    f"### 📊 3. Dashboard Interactivo de Telemetría ({selected_inc_key})"
)

with st.container():
  col_f1, col_f2, col_f3 = st.columns(3)
  with col_f1:
    sevs_disponibles = sorted(list(df_incidente["Severity"].unique()))
    filtro_sev = st.multiselect(
        "Filtrar por Severidad:",
        options=sevs_disponibles,
        default=sevs_disponibles,
    )
  with col_f2:
    hosts_en_inc = ["Todos los de la selección"] + sorted(
        list(df_incidente["Hostname"].unique())
    )
    filtro_host = st.selectbox("Filtrar por Host específico:", hosts_en_inc)
  with col_f3:
    vectores_en_inc = ["Todos los vectores"] + sorted(
        list(df_incidente["Vector_Analitico"].unique())
    )
    filtro_vec = st.selectbox("Filtrar por Vector:", vectores_en_inc)

# APLICACIÓN DE FILTROS AL DASHBOARD
df_dash = df_incidente[df_incidente["Severity"].isin(filtro_sev)].copy()
if filtro_host != "Todos los de la selección":
  df_dash = df_dash[df_dash["Hostname"] == filtro_host]
if filtro_vec != "Todos los vectores":
  df_dash = df_dash[df_dash["Vector_Analitico"] == filtro_vec]

# Tarjetas numéricas reactivas
m1, m2, m3, m4 = st.columns(4)
m1.metric("Eventos Filtrados", len(df_dash))
m2.metric(
    "Alertas High / Críticas",
    len(df_dash[df_dash["Severity"].isin(["High", "Critical"])]),
)
m3.metric("Hosts Comprometidos", df_dash["Hostname"].nunique())
m4.metric("Usuarios Activos", df_dash["User"].nunique())

d_col1, d_col2 = st.columns(2)
with d_col1:
  if not df_dash.empty:
    fig_pie = px.pie(
        df_dash,
        names="Severity",
        title="Distribución de Severidad",
        color="Severity",
        color_discrete_map={
            "High": "#DC2626",
            "Warning": "#EA580C",
            "Medium": "#D97706",
            "Informational": "#2563EB",
        },
        template="plotly_white",
    )
    fig_pie.update_layout(margin=dict(t=40, b=20, l=20, r=20))
    st.plotly_chart(fig_pie, use_container_width=True)
  else:
    st.info("Sin eventos para la combinación seleccionada.")

with d_col2:
  if not df_dash.empty:
    fig_vec = px.bar(
        df_dash.groupby("Vector_Analitico")
        .size()
        .reset_index(name="Cantidad")
        .sort_values(by="Cantidad", ascending=False),
        x="Vector_Analitico",
        y="Cantidad",
        color="Cantidad",
        color_continuous_scale="Blues",
        title="Eventos por Vector de Ataque Detectado",
        template="plotly_white",
    )
    fig_vec.update_layout(margin=dict(t=40, b=20, l=20, r=20))
    st.plotly_chart(fig_vec, use_container_width=True)

# ==========================================================
# 4. CLASIFICACIÓN DE RIESGOS (CON VECTOR COINCIDENTE DESTACADO)
# ==========================================================
st.markdown("---")
st.markdown(
    f"### ⚖️ 4. Matriz de Clasificación de Riesgos ({selected_inc_key})"
)

st.markdown(
    f"**Nivel de Riesgo Global Asignado:** `{inc_meta['risk_level']}` |"
    f" **Activos Víctima:** `{str_hosts_victimas}` | **IPs Atacantes:**"
    f" `{str_ips_atacantes}`"
)
st.warning(f"**Directiva de Respuesta Operativa:** {inc_meta['action']}")

st.markdown(
    "#### **Evaluación Heurística de Vectores (Destacado del Incidente"
    " Seleccionado):**"
)

# Lista canónica de los 6 vectores
vectores_totales = [
    {
        "nombre": "Fuerza Bruta & Credenciales",
        "mitre": "T1110 (Brute Force / Password Spraying)",
        "desc": (
            f"Fallas secuenciales EventID 4625 desde ({str_ips_atacantes}) hacia"
            f" ({str_hosts_victimas}). Cuentas: ({str_usuarios})."
        ),
        "accion": (
            f"Bloquear IPs de origen ({str_ips_atacantes}) y forzar rotación de"
            " contraseñas."
        ),
    },
    {
        "nombre": "Inicios de Sesión Sospechosos",
        "mitre": "T1078 (Valid Accounts / RDP LogonType=10)",
        "desc": (
            "Inicios de sesión remotos interactivos o con cuentas de servicio"
            f" en ({str_hosts_victimas})."
        ),
        "accion": (
            "Revocar tokens Kerberos/NTLM y aislar hosts para contención de"
            " sesión."
        ),
    },
    {
        "nombre": "Escalamiento de Privilegios",
        "mitre": "T1078 / T1069 (Permission Groups Discovery / EventID 4672)",
        "desc": (
            "Asignación anómala de privilegios de Administrador o invocación de"
            " Get-LocalGroupMember."
        ),
        "accion": (
            "Auditar asignaciones de grupos de dominio y revocar membresías"
            " sospechosas."
        ),
    },
    {
        "nombre": "Comandos y Procesos (LOLBins)",
        "mitre": (
            "T1059 (Command and Scripting Interpreter - PowerShell ofuscado /"
            " cmd.exe)"
        ),
        "desc": (
            "Ejecución de PowerShell con flags -EncodedCommand, vssadmin delete"
            " shadows o cmd.exe anómalo."
        ),
        "accion": (
            "Terminar subprocesos hijos, bloquear hashes maliciosos y aislar"
            " endpoints."
        ),
    },
    {
        "nombre": "Movimiento Lateral",
        "mitre": "T1021.002 (SMB/Windows Admin Shares / EventID 5140/5145)",
        "desc": (
            "Navegación e interconexión interna hacia recursos compartidos en"
            f" ({str_hosts_victimas})."
        ),
        "accion": (
            "Segmentar VLANs, revocar accesos SMB compartidos y deshabilitar"
            " NTLMv1."
        ),
    },
    {
        "nombre": "Otras Anomalías / Exfiltración",
        "mitre": "T1048 (Exfiltration) / T1486 (Data Encrypted for Impact)",
        "desc": (
            "Staging con tar.exe, sockets salientes hacia IPs externas públicas"
            " o destrucción masiva de backups."
        ),
        "accion": inc_meta["action"],
    },
]

# Despliegue visual destacando claramente el/los vectores que hacen MATCH con el incidente
for v in vectores_totales:
  es_match = v["nombre"] in inc_meta["matched_vectors"]
  if es_match:
    st.markdown(
        f"""
            <div class='highlight-card'>
                <span style='background-color: #2563EB; color: white; padding: 2px 8px; border-radius: 4px; font-weight: bold; font-size: 0.8rem;'>🎯 VECTOR COINCIDENTE (MATCH ACTIVO)</span>
                <h4 style='color: #1E40AF; margin-top: 6px; margin-bottom: 4px;'>{v['nombre']}</h4>
                <b>TTPs Asociadas:</b> {v['mitre']}<br/>
                <b>Evidencia Detectada:</b> {v['desc']}<br/>
                <b>Acción Inmediata:</b> <span style='color: #DC2626; font-weight: bold;'>{v['accion']}</span>
            </div>
            """,
        unsafe_allow_html=True,
    )
  else:
    st.markdown(
        f"""
            <div class='normal-card'>
                <span style='background-color: #64748B; color: white; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem;'>Línea Base / No prioritario para {selected_inc_key}</span>
                <h5 style='color: #475569; margin-top: 6px; margin-bottom: 2px;'>{v['nombre']}</h5>
                <small style='color: #64748B;'>TTP: {v['mitre']} | Estado: Monitoreado sin anomalía primaria.</small>
            </div>
            """,
        unsafe_allow_html=True,
    )

# ==========================================================
# 5. INFORME TÉCNICO DE INCIDENTE (INTEGRIDAD TOTAL)
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
  extracto = " ".join(primeras[:3]) if primeras else ""
  summary_val = (
      f"Dictamen Técnico SOC L2 para {inc_meta['title']}.\n• Activos Víctima:"
      f" {str_hosts_victimas} | IPs Atacantes: {str_ips_atacantes}\n• Vector"
      f" Coincidente Principal: {', '.join(inc_meta['matched_vectors'])}\n•"
      f" Síntesis Analítica: {extracto}"
  )
else:
  summary_val = (
      f"Durante las operaciones de monitoreo se confirmó el incidente"
      f" {inc_meta['title']} catalogado con nivel de riesgo"
      f" {inc_meta['risk_level']}.\n"
      f"• Activos Afectados (Víctimas): {str_hosts_victimas}\n"
      f"• IPs de Origen / Atacantes Detectadas ({len(ips_atacantes_detectadas)}):"
      f" {str_ips_atacantes}\n"
      f"• Cuentas Comprometidas: {str_usuarios}\n"
      f"• Vector Primario Coincidente:"
      f" {', '.join(inc_meta['matched_vectors'])}\n"
      f"• Evidencia Forense: Se correlacionaron {len(df_incidente)} eventos de"
      f" telemetría confirmando patrones de {inc_meta['mitre_technique']}.\n"
      f"• Directiva Inmediata: {inc_meta['action']}"
  )

executive_summary = st.text_area(
    "Resumen Ejecutivo del Analista (Editable):", value=summary_val, height=140
)
analyst_name = st.text_input("Analista Responsable:", value="Analista SOC Nivel 2")

# ==========================================================
# 6. EXPORTACIÓN EN PDF
# ==========================================================
st.markdown("---")
st.markdown("### 📄 6. Exportación de Informe Técnico a PDF")


def generar_pdf(
    inc_id,
    inc_titulo,
    resumen,
    analista,
    riesgo,
    attacker,
    target,
    ai_text,
    vectores_match,
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
      fontSize=15,
      textColor=colors.HexColor("#0F172A"),
      spaceAfter=12,
  )
  h2_style = ParagraphStyle(
      "H2Style",
      parent=styles["Heading2"],
      fontSize=11,
      textColor=colors.HexColor("#1E40AF"),
      spaceBefore=10,
      spaceAfter=6,
  )
  body_style = ParagraphStyle(
      "BodyStyle",
      parent=styles["Normal"],
      fontSize=9,
      leading=12.5,
      textColor=colors.HexColor("#334155"),
  )

  story = []
  story.append(
      Paragraph(
          f"INFORME TÉCNICO DE INCIDENTE - SOC NIVEL 2 ({inc_id})",
          title_style,
      )
  )
  story.append(
      Paragraph(
          f"<b>Incidente:</b> {inc_titulo}<br/>"
          f"<b>Analista:</b> {analista} | <b>Nivel de Riesgo:</b> {riesgo}<br/>"
          f"<b>Vectores Coincidentes:</b> {', '.join(vectores_match)}<br/>"
          f"<b>IPs Atacantes / Origen:</b> {attacker}<br/>"
          f"<b>Activos Víctima:</b> {target} | <b>Usuarios:</b> {str_usuarios}",
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
          f"{target} por parte de las fuentes {attacker}. Se identificaron patrones coincidentes con {', '.join(vectores_match)}."
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
          f"• Bloquear de inmediato en firewall perimetral las IPs atacantes identificadas: {attacker}.",
          body_style,
      )
  )
  story.append(
      Paragraph(
          f"• Aislar de la red los activos comprometidos ({target}) y forzar rotación de credenciales.",
          body_style,
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
      str_ips_atacantes,
      str_hosts_victimas,
      ai_text_actual,
      inc_meta["matched_vectors"],
  )
  st.download_button(
      label=f"Descargar PDF Oficial ({selected_inc_key})",
      data=pdf_buffer,
      file_name=f"informe_{selected_inc_key.lower()}_soc_l2.pdf",
      mime="application/pdf",
  )
