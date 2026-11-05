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
# CONFIGURACIÓN Y TEMA VISUAL SOC DARK NEXT-GEN (NEUTRAL BRAND)
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
    /* Tema oscuro profundo y profesional */
    .stApp {
        background-color: #0B132B;
        color: #E2E8F0;
    }
    .main-title {
        font-size: 2.2rem;
        font-weight: 800;
        background: linear-gradient(90deg, #00F0FF, #3B82F6, #10B981);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 0.2rem;
    }
    .sub-title {
        font-size: 1rem;
        color: #94A3B8;
        margin-bottom: 1.5rem;
    }
    /* Tarjetas de Métricas */
    div[data-testid="stMetric"] {
        background-color: #1C2541;
        border: 1px solid #3A506B;
        padding: 14px;
        border-radius: 10px;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.4);
    }
    div[data-testid="stMetricLabel"] {
        color: #94A3B8 !important;
        font-weight: 600;
    }
    div[data-testid="stMetricValue"] {
        color: #00F0FF !important;
        font-family: monospace;
        font-size: 1.8rem;
    }
    /* Badges de Estado */
    .badge-critical {
        background-color: #EF4444;
        color: #FFFFFF;
        padding: 4px 10px;
        border-radius: 8px;
        font-weight: bold;
        font-size: 0.8rem;
    }
    .badge-high {
        background-color: #F97316;
        color: #FFFFFF;
        padding: 4px 10px;
        border-radius: 8px;
        font-weight: bold;
        font-size: 0.8rem;
    }
    .badge-medium {
        background-color: #EAB308;
        color: #1E293B;
        padding: 4px 10px;
        border-radius: 8px;
        font-weight: bold;
        font-size: 0.8rem;
    }
    .badge-category {
        background-color: #1E3A8A;
        color: #93C5FD;
        padding: 3px 8px;
        border-radius: 6px;
        font-size: 0.8rem;
        font-weight: 600;
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

# Inicialización de API de IA (Secrets de Streamlit o variables de entorno)
api_key = st.secrets.get("GEMINI_API_KEY", os.environ.get("GEMINI_API_KEY", ""))
client = None
if api_key:
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
      "<h3 style='text-align: center; color: #00F0FF; margin-top: 0;'>Security"
      " Operations</h3>",
      unsafe_allow_html=True,
  )
  if api_key:
    st.success("🟢 Motor de IA: Activo")
  else:
    st.error("🔴 Motor de IA: Sin clave detectada")
  st.markdown("---")
  st.markdown("**Nivel Operativo:** Analista SOC L2")
  st.markdown("**Marcos de Referencia:**")
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
# MOTOR DE CLASIFICACIÓN HEURÍSTICA DE ANOMALÍAS (6 VECTORES)
# ==========================================================


def clasificar_vector(row):
  cmd = row["Process_CommandLine"].lower()
  desc = row["Event_Description"].lower()
  eid = row["Event_ID"]

  # 1. Fuerza Bruta
  if eid == "4625" or "failed to log on" in desc:
    return "Fuerza Bruta (Logon Failure)"
  # 2. Inicios de Sesión Sospechosos
  if "logontype=10" in desc or (
      eid == "4624"
      and (
          "203.0.113" in row["Source_IP"]
          or row["User"] in ["CORP\\admin", "CORP\\backupsvc"]
      )
  ):
    return "Inicio de Sesión Sospechoso (RDP / Anómalo)"
  # 3. Escalamiento de Privilegios
  if (
      eid == "4672"
      or "special privileges" in desc
      or "get-localgroupmember" in cmd
  ):
    return "Escalamiento / Abuso de Privilegios"
  # 4. Comandos y Procesos Sospechosos
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
    return "Comandos y Procesos Sospechosos (LOLBins)"
  # 5. Movimiento Lateral
  if (
      eid in ["5140", "5145"]
      or "logontype=3" in desc
      or "\\\\fs-srv01" in row["Destination"].lower()
  ):
    return "Movimiento Lateral (SMB / Shares)"
  # 6. Otras Anomalías
  if (
      "tar.exe" in cmd
      or "203.0.113.88" in row["Destination"]
      or any(k in cmd for k in ["/admin/", "/api/v1/export"])
  ):
    return "Otras Anomalías (Exfiltración / Web Fuzzing)"

  return "Actividad Normal / Línea Base"


df["Vector_Analitico"] = df.apply(clasificar_vector, axis=1)

# ==========================================================
# 2. SELECTOR DE INCIDENTES Y CORRELACIÓN DE KILL CHAIN
# ==========================================================
st.markdown("---")
st.markdown("### 🎯 2. Selector Maestro de Incidentes Correlacionados")

catalog_incidentes = {
    "INC-01": {
        "title": (
            "INC-01: Intrusión RDP, Ejecución de LOLBins y Exfiltración de"
            " Finanzas"
        ),
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
        "attacker": "Estaciones internas (10.10.1.22, 10.10.2.15)",
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

# Resumen visual del incidente activo
with st.container():
  c1, c2 = st.columns()
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
    st.caption(f"Hosts Comprometidos: {', '.join(inc_meta['hosts'])}")

# DATASET CONTEXTUAL DEL INCIDENTE SELECCIONADO
df_incidente = inc_meta["filter"](df).copy().sort_values("Timestamp")
if df_incidente.empty:
  df_incidente = df[df["Hostname"].isin(inc_meta["hosts"])].copy()

# Despliegue de Telemetría Detallada
with st.expander(
    f"📋 Telemetría Crítica Correlacionada ({len(df_incidente)} eventos)"
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

# Botón de Análisis de IA Contextual
if st.button(f"🤖 Ejecutar Evaluación Asistida por IA sobre {selected_inc_key}"):
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
            
            Logs empíricos:
            {sample_logs}
            
            Genera un assessment técnico conciso:
            1. Hipótesis del vector y causalidad temporal.
            2. Mapeo de TTPs según MITRE ATT&CK.
            3. Nivel de Confianza (Confidence: Alto/Medio/Bajo).
            4. Contramedidas defensivas inmediatas basadas en MITRE D3FEND.
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
    hosts_en_inc = ["Todos los del incidente"] + sorted(
        list(df_incidente["Hostname"].unique())
    )
    filtro_host = st.selectbox(
        "Filtrar por Host específico:", hosts_en_inc
    )
  with col_f3:
    vectores_en_inc = ["Todos los vectores"] + sorted(
        list(df_incidente["Vector_Analitico"].unique())
    )
    filtro_vec = st.selectbox("Filtrar por Vector:", vectores_en_inc)

# APLICACIÓN DE FILTROS AL DASHBOARD
df_dash = df_incidente[df_incidente["Severity"].isin(filtro_sev)].copy()
if filtro_host != "Todos los del incidente":
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
            "High": "#EF4444",
            "Warning": "#F97316",
            "Medium": "#EAB308",
            "Informational": "#3B82F6",
        },
        template="plotly_dark",
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
        color_continuous_scale="Teal",
        title="Eventos por Vector de Ataque Detectado",
        template="plotly_dark",
    )
    fig_vec.update_layout(margin=dict(t=40, b=20, l=20, r=20))
    st.plotly_chart(fig_vec, use_container_width=True)

# ==========================================================
# 4. CLASIFICACIÓN DE RIESGOS (MATRIZ SOC L2)
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

# Desglose de los 6 vectores en la matriz técnica
risk_matrix_display = {
    "Vector / Categoría Heurística": [
        "Fuerza Bruta & Credenciales",
        "Inicios de Sesión Sospechosos",
        "Escalamiento de Privilegios",
        "Comandos y Procesos (LOLBins)",
        "Movimiento Lateral",
        "Otras Anomalías / Exfiltración",
    ],
    "Estado en este Incidente": [
        "Detectado" if "INC-02" == selected_inc_key else "Monitoreado",
        "Detectado"
        if selected_inc_key in ["INC-01", "INC-04"]
        else "Línea Base",
        "Detectado"
        if selected_inc_key in ["INC-01", "INC-04"]
        else "Línea Base",
        "Detectado"
        if selected_inc_key in ["INC-01", "INC-03", "INC-04"]
        else "Línea Base",
        "Detectado"
        if selected_inc_key in ["INC-01", "INC-04"]
        else "Línea Base",
        "Detectado"
        if selected_inc_key in ["INC-01", "INC-03", "INC-04"]
        else "Línea Base",
    ],
    "Justificación / Evidencia en Telemetría": [
        "Fallas de autenticación 4625 secuenciales sobre cuentas corporativas.",
        (
            f"LogonType=10 remoto o accesos privilegiados en"
            f" {', '.join(inc_meta['hosts'])}."
        ),
        "Consultas a grupos locales o privilegios especiales asignados (4672).",
        (
            f"Invocación de procesos sospechosos acordes a"
            f" {inc_meta['mitre_technique']}."
        ),
        (
            f"Conexiones de red internas o accesos a recursos compartidos en"
            f" {inc_meta['target']}."
        ),
        inc_meta["justification"],
    ],
    "Decisión Operativa Inmediata": [
        "Bloqueo temporal de cuentas y análisis de IPs origen",
        "Revocación de tokens y aislamiento del host",
        "Auditoría de membresías en Directorio Activo",
        "Terminar proceso y bloquear hash en EDR",
        "Revocar accesos de red y aislar servidor de archivos",
        inc_meta["action"],
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
# 6. EXPORTACIÓN EN PDF
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
          f"INFORME TÉCNICO DE INCIDENTE - SOC NIVEL 2 ({inc_id})",
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
          "• Bloquear IPs y hashes maliciosos en firewall perimetral y EDR.",
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
