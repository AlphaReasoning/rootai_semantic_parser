import streamlit as st
import os
import tempfile
import subprocess
import zipfile
from async_parse import scan_async

# Sovereign Branding
st.set_page_config(page_title="RootAI Command Deck", page_icon="🛡️", layout="wide")
st.title("🛡️ RootAI: Sovereign Command Deck")

# Sidebar Configuration
st.sidebar.header("📡 Configuration")
profile = st.sidebar.selectbox("Finding Profile", ["human-only", "ai-only", "full-spectrum"])
min_score = st.sidebar.slider("Minimum Severity Score", 0.0, 10.0, 6.5)

# --- INGESTION LAYER ---
st.subheader("📁 Ingest Source File System")
tab1, tab2 = st.tabs(["Clone Public URL", "Upload Archive (.zip)"])

# We use session_state to keep the workspace alive between button clicks
if 'workspace_path' not in st.session_state:
    st.session_state.workspace_path = None

with tab1:
    repo_url = st.text_input("Public Git URL", placeholder="https://github.com/username/repo")
    if st.button("Clone & Prep"):
        if repo_url:
            with st.spinner("Executing Git Clone..."):
                tmp_dir = tempfile.mkdtemp()
                try:
                    # git clone --depth 1 is high-velocity for large repos
                    subprocess.run(["git", "clone", "--depth", "1", repo_url, tmp_dir], check=True)
                    st.session_state.workspace_path = tmp_dir
                    st.success(f"Repository cloned to virtual workspace.")
                except Exception as e:
                    st.error(f"Clone failed: {e}")

with tab2:
    uploaded_zip = st.file_uploader("Upload Source Archive", type=["zip"])
    if uploaded_zip and st.button("Extract & Prep"):
        with st.spinner("Unpacking archive..."):
            tmp_dir = tempfile.mkdtemp()
            zip_path = os.path.join(tmp_dir, "upload.zip")
            with open(zip_path, "wb") as f:
                f.write(uploaded_zip.getbuffer())
            
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(tmp_dir)
            st.session_state.workspace_path = tmp_dir
            st.success("Archive extracted to virtual workspace.")

# --- ANALYSIS LAYER ---
if st.session_state.workspace_path:
    st.markdown("---")
    st.info(f"Workspace Active: `{st.session_state.workspace_path}`")
    
    if st.button("Execute Semantic Scan"):
        with st.spinner("Walking file system and mapping semantic intent..."):
            try:
                # IMPORTANT: ensure scan_async accepts a directory path as the first argument
                results = scan_async(st.session_state.workspace_path, profile=profile, min_score=min_score)
                
                st.subheader("🔍 Analysis Results")
                if results:
                    st.json(results)
                else:
                    st.warning("No significant vulnerabilities or logic flaws detected.")
            except Exception as e:
                st.error(f"Scan interrupted: {e}")
else:
    st.write("Awaiting source ingestion. Point the deck at a repository or upload an archive.")

st.markdown("---")
st.caption("alpha-reasoning lab | Loyal Rameriz LLC | 2026-04-17")
