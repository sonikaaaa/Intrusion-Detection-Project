import streamlit as st
import requests

st.set_page_config(page_title="Network Intrusion Detection", layout="centered")

st.title("🔒 Network Intrusion Detection System")
st.write("Enter connection details below to check if it's normal traffic or a potential attack.")

API_URL = "https://intrusion-detection-project-k5fg.onrender.com/predict"

# ---- Preset example patterns ----
PRESETS = {
    "normal": {
        "duration": 0, "protocol_type": "tcp", "service": "http", "flag": "SF",
        "src_bytes": 200, "dst_bytes": 500, "land": 0, "wrong_fragment": 0, "urgent": 0, "hot": 0,
        "num_failed_logins": 0, "logged_in": 1, "num_compromised": 0, "root_shell": 0, "su_attempted": 0,
        "num_root": 0, "num_file_creations": 0, "num_shells": 0, "num_access_files": 0,
        "num_outbound_cmds": 0, "is_host_login": 0, "is_guest_login": 0, "count": 1, "srv_count": 1,
        "serror_rate": 0.0, "srv_serror_rate": 0.0, "rerror_rate": 0.0, "srv_rerror_rate": 0.0,
        "same_srv_rate": 1.0, "diff_srv_rate": 0.0, "srv_diff_host_rate": 0.0,
        "dst_host_count": 1, "dst_host_srv_count": 1, "dst_host_same_srv_rate": 1.0,
        "dst_host_diff_srv_rate": 0.0, "dst_host_same_src_port_rate": 0.0,
        "dst_host_srv_diff_host_rate": 0.0, "dst_host_serror_rate": 0.0,
        "dst_host_srv_serror_rate": 0.0, "dst_host_rerror_rate": 0.0, "dst_host_srv_rerror_rate": 0.0,
    },
    "dos": {
        "duration": 0, "protocol_type": "tcp", "service": "private", "flag": "S0",
        "src_bytes": 0, "dst_bytes": 0, "land": 0, "wrong_fragment": 0, "urgent": 0, "hot": 0,
        "num_failed_logins": 0, "logged_in": 0, "num_compromised": 0, "root_shell": 0, "su_attempted": 0,
        "num_root": 0, "num_file_creations": 0, "num_shells": 0, "num_access_files": 0,
        "num_outbound_cmds": 0, "is_host_login": 0, "is_guest_login": 0, "count": 200, "srv_count": 200,
        "serror_rate": 1.0, "srv_serror_rate": 1.0, "rerror_rate": 0.0, "srv_rerror_rate": 0.0,
        "same_srv_rate": 1.0, "diff_srv_rate": 0.0, "srv_diff_host_rate": 0.0,
        "dst_host_count": 255, "dst_host_srv_count": 255, "dst_host_same_srv_rate": 1.0,
        "dst_host_diff_srv_rate": 0.0, "dst_host_same_src_port_rate": 0.0,
        "dst_host_srv_diff_host_rate": 0.0, "dst_host_serror_rate": 1.0,
        "dst_host_srv_serror_rate": 1.0, "dst_host_rerror_rate": 0.0, "dst_host_srv_rerror_rate": 0.0,
    },
    "probe": {
        "duration": 0, "protocol_type": "tcp", "service": "private", "flag": "REJ",
        "src_bytes": 0, "dst_bytes": 0, "land": 0, "wrong_fragment": 0, "urgent": 0, "hot": 0,
        "num_failed_logins": 0, "logged_in": 0, "num_compromised": 0, "root_shell": 0, "su_attempted": 0,
        "num_root": 0, "num_file_creations": 0, "num_shells": 0, "num_access_files": 0,
        "num_outbound_cmds": 0, "is_host_login": 0, "is_guest_login": 0, "count": 50, "srv_count": 1,
        "serror_rate": 0.0, "srv_serror_rate": 0.0, "rerror_rate": 1.0, "srv_rerror_rate": 1.0,
        "same_srv_rate": 0.02, "diff_srv_rate": 0.98, "srv_diff_host_rate": 0.0,
        "dst_host_count": 255, "dst_host_srv_count": 5, "dst_host_same_srv_rate": 0.02,
        "dst_host_diff_srv_rate": 0.98, "dst_host_same_src_port_rate": 0.0,
        "dst_host_srv_diff_host_rate": 0.0, "dst_host_serror_rate": 0.0,
        "dst_host_srv_serror_rate": 0.0, "dst_host_rerror_rate": 1.0, "dst_host_srv_rerror_rate": 1.0,
    },
    "r2l": {
        "duration": 280, "protocol_type": "tcp", "service": "ftp", "flag": "SF",
        "src_bytes": 300, "dst_bytes": 8000, "land": 0, "wrong_fragment": 0, "urgent": 0, "hot": 1,
        "num_failed_logins": 2, "logged_in": 0, "num_compromised": 0, "root_shell": 0, "su_attempted": 0,
        "num_root": 0, "num_file_creations": 0, "num_shells": 0, "num_access_files": 0,
        "num_outbound_cmds": 0, "is_host_login": 0, "is_guest_login": 0, "count": 1, "srv_count": 1,
        "serror_rate": 0.0, "srv_serror_rate": 0.0, "rerror_rate": 0.0, "srv_rerror_rate": 0.0,
        "same_srv_rate": 1.0, "diff_srv_rate": 0.0, "srv_diff_host_rate": 0.16,
        "dst_host_count": 1, "dst_host_srv_count": 1, "dst_host_same_srv_rate": 1.0,
        "dst_host_diff_srv_rate": 0.0, "dst_host_same_src_port_rate": 1.0,
        "dst_host_srv_diff_host_rate": 0.16, "dst_host_serror_rate": 0.0,
        "dst_host_srv_serror_rate": 0.0, "dst_host_rerror_rate": 0.0, "dst_host_srv_rerror_rate": 0.0,
    },
    "u2r": {
        "duration": 500, "protocol_type": "tcp", "service": "telnet", "flag": "SF",
        "src_bytes": 1500, "dst_bytes": 3000, "land": 0, "wrong_fragment": 0, "urgent": 0, "hot": 3,
        "num_failed_logins": 0, "logged_in": 1, "num_compromised": 1, "root_shell": 1, "su_attempted": 1,
        "num_root": 2, "num_file_creations": 2, "num_shells": 1, "num_access_files": 1,
        "num_outbound_cmds": 0, "is_host_login": 0, "is_guest_login": 0, "count": 1, "srv_count": 1,
        "serror_rate": 0.0, "srv_serror_rate": 0.0, "rerror_rate": 0.0, "srv_rerror_rate": 0.0,
        "same_srv_rate": 1.0, "diff_srv_rate": 0.0, "srv_diff_host_rate": 0.0,
        "dst_host_count": 1, "dst_host_srv_count": 1, "dst_host_same_srv_rate": 1.0,
        "dst_host_diff_srv_rate": 0.0, "dst_host_same_src_port_rate": 1.0,
        "dst_host_srv_diff_host_rate": 0.0, "dst_host_serror_rate": 0.0,
        "dst_host_srv_serror_rate": 0.0, "dst_host_rerror_rate": 0.0, "dst_host_srv_rerror_rate": 0.0,
    },
}

if "form_values" not in st.session_state:
    st.session_state.form_values = PRESETS["normal"].copy()

st.subheader("Quick Examples")
col1, col2, col3, col4, col5 = st.columns(5)
with col1:
    if st.button("✅ Normal"):
        st.session_state.form_values = PRESETS["normal"].copy()
        st.rerun()
with col2:
    if st.button("🚨 DoS"):
        st.session_state.form_values = PRESETS["dos"].copy()
        st.rerun()
with col3:
    if st.button("🚨 Probe"):
        st.session_state.form_values = PRESETS["probe"].copy()
        st.rerun()
with col4:
    if st.button("🚨 R2L"):
        st.session_state.form_values = PRESETS["r2l"].copy()
        st.rerun()
with col5:
    if st.button("🚨 U2R"):
        st.session_state.form_values = PRESETS["u2r"].copy()
        st.rerun()

st.divider()

v = st.session_state.form_values

with st.form("connection_form"):
    st.subheader("Basic Connection Info")
    col1, col2 = st.columns(2)
    with col1:
        duration = st.number_input("Duration", min_value=0.0, value=float(v["duration"]))
        protocol_type = st.selectbox("Protocol Type", ["tcp", "udp", "icmp"],
                                      index=["tcp", "udp", "icmp"].index(v["protocol_type"]))
        service_options = ["http", "ftp_data", "ftp", "private", "smtp", "telnet", "domain_u", "other"]
        service_val = v["service"] if v["service"] in service_options else "other"
        service = st.selectbox("Service", service_options, index=service_options.index(service_val))
        flag_options = ["SF", "S0", "REJ", "RSTR", "SH", "RSTO", "S1", "RSTOS0", "S3", "S2", "OTH"]
        flag = st.selectbox("Flag", flag_options, index=flag_options.index(v["flag"]))
    with col2:
        src_bytes = st.number_input("Source Bytes", min_value=0.0, value=float(v["src_bytes"]))
        dst_bytes = st.number_input("Destination Bytes", min_value=0.0, value=float(v["dst_bytes"]))
        logged_in = st.selectbox("Logged In?", [0, 1], index=v["logged_in"])
        count = st.number_input("Connection Count", min_value=0, value=int(v["count"]))

    st.subheader("Advanced (auto-filled by presets above)")
    with st.expander("Show advanced fields"):
        land = st.number_input("Land", min_value=0, value=int(v["land"]))
        wrong_fragment = st.number_input("Wrong Fragment", min_value=0, value=int(v["wrong_fragment"]))
        urgent = st.number_input("Urgent", min_value=0, value=int(v["urgent"]))
        hot = st.number_input("Hot", min_value=0, value=int(v["hot"]))
        num_failed_logins = st.number_input("Num Failed Logins", min_value=0, value=int(v["num_failed_logins"]))
        num_compromised = st.number_input("Num Compromised", min_value=0, value=int(v["num_compromised"]))
        root_shell = st.number_input("Root Shell", min_value=0, value=int(v["root_shell"]))
        su_attempted = st.number_input("Su Attempted", min_value=0, value=int(v["su_attempted"]))
        num_root = st.number_input("Num Root", min_value=0, value=int(v["num_root"]))
        num_file_creations = st.number_input("Num File Creations", min_value=0, value=int(v["num_file_creations"]))
        num_shells = st.number_input("Num Shells", min_value=0, value=int(v["num_shells"]))
        num_access_files = st.number_input("Num Access Files", min_value=0, value=int(v["num_access_files"]))
        num_outbound_cmds = st.number_input("Num Outbound Cmds", min_value=0, value=int(v["num_outbound_cmds"]))
        is_host_login = st.number_input("Is Host Login", min_value=0, value=int(v["is_host_login"]))
        is_guest_login = st.number_input("Is Guest Login", min_value=0, value=int(v["is_guest_login"]))
        srv_count = st.number_input("Srv Count", min_value=0, value=int(v["srv_count"]))
        serror_rate = st.slider("Serror Rate", 0.0, 1.0, float(v["serror_rate"]))
        srv_serror_rate = st.slider("Srv Serror Rate", 0.0, 1.0, float(v["srv_serror_rate"]))
        rerror_rate = st.slider("Rerror Rate", 0.0, 1.0, float(v["rerror_rate"]))
        srv_rerror_rate = st.slider("Srv Rerror Rate", 0.0, 1.0, float(v["srv_rerror_rate"]))
        same_srv_rate = st.slider("Same Srv Rate", 0.0, 1.0, float(v["same_srv_rate"]))
        diff_srv_rate = st.slider("Diff Srv Rate", 0.0, 1.0, float(v["diff_srv_rate"]))
        srv_diff_host_rate = st.slider("Srv Diff Host Rate", 0.0, 1.0, float(v["srv_diff_host_rate"]))
        dst_host_count = st.number_input("Dst Host Count", min_value=0, value=int(v["dst_host_count"]))
        dst_host_srv_count = st.number_input("Dst Host Srv Count", min_value=0, value=int(v["dst_host_srv_count"]))
        dst_host_same_srv_rate = st.slider("Dst Host Same Srv Rate", 0.0, 1.0, float(v["dst_host_same_srv_rate"]))
        dst_host_diff_srv_rate = st.slider("Dst Host Diff Srv Rate", 0.0, 1.0, float(v["dst_host_diff_srv_rate"]))
        dst_host_same_src_port_rate = st.slider("Dst Host Same Src Port Rate", 0.0, 1.0, float(v["dst_host_same_src_port_rate"]))
        dst_host_srv_diff_host_rate = st.slider("Dst Host Srv Diff Host Rate", 0.0, 1.0, float(v["dst_host_srv_diff_host_rate"]))
        dst_host_serror_rate = st.slider("Dst Host Serror Rate", 0.0, 1.0, float(v["dst_host_serror_rate"]))
        dst_host_srv_serror_rate = st.slider("Dst Host Srv Serror Rate", 0.0, 1.0, float(v["dst_host_srv_serror_rate"]))
        dst_host_rerror_rate = st.slider("Dst Host Rerror Rate", 0.0, 1.0, float(v["dst_host_rerror_rate"]))
        dst_host_srv_rerror_rate = st.slider("Dst Host Srv Rerror Rate", 0.0, 1.0, float(v["dst_host_srv_rerror_rate"]))

    submitted = st.form_submit_button("🔍 Analyze Connection")

if submitted:
    payload = {
        "duration": duration, "protocol_type": protocol_type, "service": service, "flag": flag,
        "src_bytes": src_bytes, "dst_bytes": dst_bytes, "land": land, "wrong_fragment": wrong_fragment,
        "urgent": urgent, "hot": hot, "num_failed_logins": num_failed_logins, "logged_in": logged_in,
        "num_compromised": num_compromised, "root_shell": root_shell, "su_attempted": su_attempted,
        "num_root": num_root, "num_file_creations": num_file_creations, "num_shells": num_shells,
        "num_access_files": num_access_files, "num_outbound_cmds": num_outbound_cmds,
        "is_host_login": is_host_login, "is_guest_login": is_guest_login, "count": count,
        "srv_count": srv_count, "serror_rate": serror_rate, "srv_serror_rate": srv_serror_rate,
        "rerror_rate": rerror_rate, "srv_rerror_rate": srv_rerror_rate, "same_srv_rate": same_srv_rate,
        "diff_srv_rate": diff_srv_rate, "srv_diff_host_rate": srv_diff_host_rate,
        "dst_host_count": dst_host_count, "dst_host_srv_count": dst_host_srv_count,
        "dst_host_same_srv_rate": dst_host_same_srv_rate, "dst_host_diff_srv_rate": dst_host_diff_srv_rate,
        "dst_host_same_src_port_rate": dst_host_same_src_port_rate,
        "dst_host_srv_diff_host_rate": dst_host_srv_diff_host_rate,
        "dst_host_serror_rate": dst_host_serror_rate, "dst_host_srv_serror_rate": dst_host_srv_serror_rate,
        "dst_host_rerror_rate": dst_host_rerror_rate, "dst_host_srv_rerror_rate": dst_host_srv_rerror_rate,
    }

    try:
        response = requests.post(API_URL, json=payload)
        if response.status_code == 200:
            result = response.json()
            prediction = result["prediction"]

            if prediction == "normal":
                st.success(f"✅ Prediction: **{prediction.upper()}** (Confidence: {result['confidence']*100:.1f}%)")
            else:
                st.error(f"🚨 Prediction: **{prediction.upper()}** attack detected (Confidence: {result['confidence']*100:.1f}%)")

            st.subheader("Why this prediction? (Top contributing factors)")
            factors = result["top_contributing_factors"]
            for feature, value in factors.items():
                direction = "pushed toward this prediction" if value > 0 else "pushed away from this prediction"
                st.write(f"- **{feature}**: {value:.3f} ({direction})")
        else:
            st.error(f"API Error: {response.status_code} - {response.text}")
    except requests.exceptions.ConnectionError:
        st.error("⚠️ Could not connect to the API. Make sure your FastAPI server (uvicorn) is running.")