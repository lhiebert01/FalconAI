import streamlit as st
import pandas as pd
import datetime
import os
import json
import requests
import base64
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# --- Configuration ---
st.set_page_config(
    page_title="CrowdStrike SOC AI Assistant",
    page_icon="🛡️",
    layout="wide",  # Use wide layout for better dashboard feel
    initial_sidebar_state="expanded"
)

# --- API Key Configuration ---
# Hidden from user interface - automatically use environment variables or secrets
try:
    # Priority order: Environment variable > Streamlit secrets
    if os.environ.get("GOOGLE_API_KEY"):
        GEMINI_API_KEY = os.environ.get("GOOGLE_API_KEY")
    elif "GOOGLE_API_KEY" in st.secrets:
        GEMINI_API_KEY = st.secrets["GOOGLE_API_KEY"]
    else:
        st.error("Google API key not found. Please add it to environment variables or Streamlit secrets.", icon="⚠️")
        GEMINI_API_KEY = None
    
    # No manual key entry UI - using only secured sources
    gemini_available = False
    if GEMINI_API_KEY:
        # Test with a minimal query using direct REST API
        try:
            url = "https://generativelanguage.googleapis.com/v1/models/gemini-2.0-flash-001:generateContent"
            headers = {
                "Content-Type": "application/json",
                "x-goog-api-key": GEMINI_API_KEY
            }
            data = {
                "contents": [
                    {
                        "parts": [
                            {
                                "text": "Hello"
                            }
                        ]
                    }
                ]
            }
            
            response = requests.post(url, headers=headers, json=data)
            
            if response.status_code == 200:
                gemini_available = True
                st.sidebar.success("Gemini API connected successfully! ✅")
            else:
                st.sidebar.error(f"Gemini API test failed: Status code {response.status_code}")
                st.sidebar.code(response.text)
        except Exception as e:
            st.sidebar.error(f"Gemini API test failed: {str(e)}")
            
except Exception as e:
    st.error(f"Error configuring Gemini API: {str(e)}. Please ensure your API key is valid.", icon="⚠️")
    gemini_available = False

# --- Gemini Model Configuration ---
# Fixed model setting - no user selection since one option is deprecated
if 'model_name' not in st.session_state:
    st.session_state.model_name = 'gemini-2.0-flash-001'

# Display model info in sidebar
st.sidebar.header("Model Information")
st.sidebar.info(f"Using model: gemini-2.0-flash-001")

# --- Helper Functions ---
def download_chat_history(chat_history):
    """Generate a download link for the chat history"""
    if not chat_history:
        return "No chat history to download"
    
    # Format chat history
    timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    history_text = f"CrowdStrike SOC AI Assistant Chat - {timestamp}\n\n"
    
    for entry in chat_history:
        history_text += f"Q: {entry['question']}\n"
        history_text += f"A: {entry['answer']}\n\n"
    
    # Create download link
    b64 = base64.b64encode(history_text.encode()).decode()
    href = f'<a href="data:text/plain;base64,{b64}" download="soc_chat_{timestamp}.txt">Download Chat History</a>'
    return href

def ask_gemini(prompt, chat_history=None):
    """Sends a prompt to Gemini and returns the response using direct REST API."""
    if not gemini_available:
        return "Gemini AI is not available. Please check configuration and API key."
    try:
        # Add some additional error handling and retry logic
        max_retries = 3
        retry_count = 0
        last_error = None
        
        # Use session state for model name
        current_model_name = st.session_state.model_name
        
        while retry_count < max_retries:
            try:
                url = f"https://generativelanguage.googleapis.com/v1/models/{current_model_name}:generateContent"
                headers = {
                    "Content-Type": "application/json",
                    "x-goog-api-key": GEMINI_API_KEY
                }
                
                # Include chat history if provided
                contents = []
                if chat_history:
                    for entry in chat_history:
                        contents.append({"role": "user", "parts": [{"text": entry["question"]}]})
                        contents.append({"role": "model", "parts": [{"text": entry["answer"]}]})
                
                # Add current prompt
                contents.append({"role": "user", "parts": [{"text": prompt}]})
                
                data = {
                    "contents": contents if contents else [
                        {
                            "parts": [
                                {
                                    "text": prompt
                                }
                            ]
                        }
                    ],
                    "generationConfig": {
                        "temperature": 0.7,
                        "topK": 40,
                        "topP": 0.95,
                        "maxOutputTokens": 2048
                    },
                    "safetySettings": [
                        {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_MEDIUM_AND_ABOVE"},
                        {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_MEDIUM_AND_ABOVE"},
                        {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_MEDIUM_AND_ABOVE"},
                        {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_MEDIUM_AND_ABOVE"}
                    ]
                }
                
                response = requests.post(url, headers=headers, json=data)
                
                if response.status_code == 200:
                    response_json = response.json()
                    if 'candidates' in response_json and len(response_json['candidates']) > 0:
                        content = response_json['candidates'][0]['content']
                        if 'parts' in content and len(content['parts']) > 0:
                            return content['parts'][0]['text']
                        else:
                            return "Received an empty response from Gemini."
                    else:
                        return "Unexpected response format from Gemini API."
                else:
                    last_error = f"API error: Status code {response.status_code} - {response.text}"
                    retry_count += 1
                    if retry_count < max_retries:
                        st.warning(f"API call failed, retrying ({retry_count}/{max_retries})...")
                        # Wait a short time before retrying
                        import time
                        time.sleep(1)
                    else:
                        return f"Error communicating with Gemini AI: {last_error}"
            except Exception as e:
                last_error = str(e)
                retry_count += 1
                if retry_count < max_retries:
                    st.warning(f"API call failed, retrying ({retry_count}/{max_retries})...")
                    # Wait a short time before retrying
                    import time
                    time.sleep(1)
                else:
                    return f"Error communicating with Gemini AI: {last_error}"
        
        # If we get here, all retries failed
        return f"Gemini API request failed after {max_retries} attempts: {last_error}"
    except Exception as e:
        st.error(f"Gemini API request failed: {e}")
        return f"Error communicating with Gemini AI: {str(e)}"

# --- Data Simulation ---
def get_simulated_alerts():
    now = datetime.datetime.now(datetime.timezone.utc)
    return [
        {
            "id": "ALERT001",
            "title": "Multi-Stage Ransomware Attack Detected",
            "type": ["Behavioral Detection", "Ransomware"],
            "severity": 10,
            "timestamp": (now - datetime.timedelta(minutes=30)).isoformat(),
            "affected_hosts": [{"hostname": "FIN-SRV-01", "ip": "10.1.10.5"}, {"hostname": "MKT-WS-15", "ip": "10.1.20.12"}],
            "key_processes": ["powershell.exe", "svchost.exe", "cryptXXX.exe"],
            "iocs": [
                {"type": "SHA256", "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}, # Example hash
                {"type": "IP Address", "value": "185.141.25.178"}, # Example C2
                {"type": "Registry Key", "value": r"HKCU\Software\CryptoLocker\Files"}
            ],
            "mitre_ttps": ["T1059.001", "T1547.001", "T1486"],
            "cs_action": ["Blocked Process", "Quarantined Host (FIN-SRV-01)"],
            "status": "Action Required"
        },
        {
            "id": "ALERT002",
            "title": "Credential Dumping & Lateral Movement Attempt",
            "type": ["Credential Access", "Lateral Movement"],
            "severity": 8,
            "timestamp": (now - datetime.timedelta(hours=2)).isoformat(),
            "source_host": {"hostname": "DEV-WS-03", "ip": "10.2.5.18"},
            "target_hosts": [{"hostname": "DC-01", "ip": "10.0.0.5"}, {"hostname": "APP-SRV-02", "ip": "10.1.15.8"}],
            "user_account": r"domain\lowpriv_user -> domain\admin_svc",
            "key_processes": ["lsass.exe", "wmic.exe", "psexec.exe"],
            "iocs": [
                {"type": "Behavior", "value": "Mimikatz-like behavior targeting lsass.exe"},
                {"type": "Network Connection", "value": "10.2.5.18 -> 10.0.0.5 (Port 445)"}
            ],
            "mitre_ttps": ["T1003.001", "T1021.002"],
            "cs_action": ["Blocked Process (wmic.exe)", "Detected Credential Access"],
            "status": "Investigation Suggested"
        },
        {
            "id": "ALERT003",
            "title": "Suspicious Outbound Connection to Known Malicious Domain",
            "type": ["Command and Control", "Network Detection"],
            "severity": 7,
            "timestamp": (now - datetime.timedelta(minutes=45)).isoformat(),
            "affected_hosts": [{"hostname": "HR-WS-05", "ip": "10.1.30.25"}],
            "key_processes": ["chrome.exe"],
            "iocs": [
                {"type": "Domain", "value": "badguy-updates.ru"}, # Example bad domain
                {"type": "IP Address", "value": "93.184.216.34"}, # Example IP for bad domain
                {"type": "Behavior", "value": "Beaconing pattern detected"}
            ],
            "mitre_ttps": ["T1071.001", "T1105"],
            "cs_action": ["Detected Network Connection", "Blocked Domain (Simulated)"],
            "status": "Monitor"
        },
        # Add more simulated "daily/lower priority" items if needed
        {
            "id": "INFO001",
            "title": "Intelligence Report: New Phishing Campaign",
            "type": ["Intel"],
            "severity": 4,
            "timestamp": (now - datetime.timedelta(hours=6)).isoformat(),
            "summary": "CrowdStrike Intelligence identified a new phishing campaign targeting financial institutions using lures related to tax documents. Associated IoCs are being monitored.",
             "iocs": [
                {"type": "URL", "value": "http://secure-doc-portal.xyz/login"},
                {"type": "SHA256", "value": "a1b2c3d4..."}
            ],
             "status": "Informational"
        }
    ]

def severity_badge(severity):
    if severity >= 9: return "🔴 Critical"
    if severity >= 7: return "🟠 High"
    if severity >= 4: return "🟡 Medium"
    return "⚪ Low"

def format_alert_details(alert):
    """Formats alert dictionary into a readable string for display or AI"""
    details = f"**Alert ID:** {alert['id']}\n"
    details += f"**Title:** {alert['title']}\n"
    details += f"**Severity:** {alert['severity']}/10 ({severity_badge(alert['severity'])})\n"
    details += f"**Timestamp:** {alert['timestamp']}\n"
    details += f"**Type:** {', '.join(alert.get('type', []))}\n"
    if 'affected_hosts' in alert:
        hosts = [f"{h['hostname']} ({h['ip']})" for h in alert['affected_hosts']]
        details += f"**Affected Hosts:** {', '.join(hosts)}\n"
    if 'source_host' in alert:
         details += f"**Source Host:** {alert['source_host']['hostname']} ({alert['source_host']['ip']})\n"
    if 'target_hosts' in alert:
        targets = [f"{h['hostname']} ({h['ip']})" for h in alert['target_hosts']]
        details += f"**Target Hosts:** {', '.join(targets)}\n"
    if 'user_account' in alert:
        details += f"**User Account:** {alert['user_account']}\n"
    if 'key_processes' in alert:
        details += f"**Key Processes:** {', '.join(alert.get('key_processes', []))}\n"
    if 'iocs' in alert:
        details += "**Indicators of Compromise:**\n"
        for ioc in alert['iocs']:
             details += f"- {ioc['type']}: `{ioc['value']}`\n" # Use markdown code formatting
    if 'mitre_ttps' in alert:
        details += f"**MITRE ATT&CK TTPs:** {', '.join(alert.get('mitre_ttps', []))}\n"
    if 'cs_action' in alert:
        details += f"**CrowdStrike Action:** {', '.join(alert.get('cs_action', []))}\n"
    if 'summary' in alert:
         details += f"**Summary:** {alert.get('summary')}\n"
    details += f"**Status:** {alert.get('status', 'N/A')}\n"
    return details

# --- Initialize Chat History ---
if 'chat_history' not in st.session_state:
    st.session_state.chat_history = []

# --- App Layout ---

st.title("🛡️ Simulated CrowdStrike SOC Dashboard")
st.caption(f"Powered by Streamlit & Google Gemini AI | Last Refresh: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

# --- Sidebar ---
st.sidebar.header("Navigation")
view_mode = st.sidebar.radio("Select View", ["High-Priority Alerts", "Full Alert Feed", "AI Assistant"])
st.sidebar.markdown("---")
st.sidebar.info("This is a simulated demo application showcasing potential GenAI integration with CrowdStrike-like data.")

# --- Load Data ---
alerts_data = get_simulated_alerts()
alerts_df = pd.DataFrame(alerts_data)

# --- Main Content Area ---

if view_mode == "High-Priority Alerts":
    st.header("🚨 High-Priority Alerts (Severity >= 7)")
    high_priority_alerts = [a for a in alerts_data if a['severity'] >= 7]

    if not high_priority_alerts:
        st.info("No high-priority alerts detected currently.")
    else:
        for alert in sorted(high_priority_alerts, key=lambda x: x['severity'], reverse=True):
            expander_title = f"{severity_badge(alert['severity'])} - {alert['title']} ({alert['id']})"
            with st.expander(expander_title, expanded=alert['severity']>=9): # Expand critical ones by default
                st.markdown(format_alert_details(alert))

                st.markdown("---")
                st.subheader("🤖 Gemini AI Analysis")

                col1, col2, col3 = st.columns(3)
                with col1:
                    if st.button("Summarize Risk", key=f"summary_{alert['id']}"):
                        prompt = f"You are a helpful SOC assistant. Summarize the key risks and potential impact of the following security alert in 2-3 bullet points. Focus on business impact if possible.\n\nAlert Data:\n{format_alert_details(alert)}"
                        with st.spinner("Asking Gemini..."):
                            response = ask_gemini(prompt)
                        st.markdown(response)
                with col2:
                    if st.button("Suggest Actions", key=f"actions_{alert['id']}"):
                        prompt = f"You are a helpful SOC assistant. Based on the following security alert, suggest 3 immediate, actionable steps a SOC analyst should take.\n\nAlert Data:\n{format_alert_details(alert)}"
                        with st.spinner("Asking Gemini..."):
                            response = ask_gemini(prompt)
                        st.markdown(response)
                with col3:
                     if st.button("Explain IoCs/TTPs", key=f"explain_{alert['id']}"):
                        prompt = f"You are a helpful SOC assistant. Briefly explain the significance of the IoCs and MITRE ATT&CK TTPs listed in this alert in simple terms.\n\nAlert Data:\n{format_alert_details(alert)}"
                        with st.spinner("Asking Gemini..."):
                            response = ask_gemini(prompt)
                        st.markdown(response)

elif view_mode == "Full Alert Feed":
    st.header("📄 Full Alert & Information Feed")
    st.info("Displaying all simulated alerts and informational reports.")

    # Add filtering options
    st.markdown("Filter Options:")
    col1, col2 = st.columns(2)
    with col1:
        sev_filter = st.multiselect("Filter by Severity:", options=[10, 9, 8, 7, 6, 5, 4, 3, 2, 1], default=[10,9,8,7]) # Default high/crit
    with col2:
        type_list = sorted(list(set(t for alert in alerts_data for t in alert.get('type',[]))))
        type_filter = st.multiselect("Filter by Type:", options=type_list)

    # Apply filters
    filtered_alerts = alerts_data
    if sev_filter:
        filtered_alerts = [a for a in filtered_alerts if a['severity'] in sev_filter]
    if type_filter:
        filtered_alerts = [a for a in filtered_alerts if any(t in type_filter for t in a.get('type',[]))]


    if not filtered_alerts:
         st.warning("No alerts match the current filter criteria.")
    else:
        # Display as a table or cards
        st.dataframe(pd.DataFrame(filtered_alerts), use_container_width=True) # Simple table view

        st.markdown("---")
        st.subheader("Detailed View (Select Alert)")
        alert_ids = [a['id'] for a in filtered_alerts]
        selected_id = st.selectbox("Select Alert ID for details:", options=alert_ids)

        if selected_id:
            selected_alert = next((a for a in filtered_alerts if a['id'] == selected_id), None)
            if selected_alert:
                st.markdown(format_alert_details(selected_alert))
                # Add Gemini interaction buttons here too if desired

elif view_mode == "AI Assistant":
    st.header("💬 AI Assistant (Powered by Gemini)")
    st.info("Ask questions about the simulated security posture or specific alerts/IoCs.")

    # Example questions with functional buttons
    st.markdown("**Example Questions:**")
    example_questions = [
        "What are the top 3 critical risks right now?",
        "Explain the ransomware alert ALERT001.",
        "What is the risk associated with the IP address 185.141.25.178?",
        "Are there any alerts related to lateral movement?"
    ]
    
    # Create columns for example question buttons
    cols = st.columns(2)
    for i, question in enumerate(example_questions):
        if cols[i % 2].button(question, key=f"example_{i}"):
            # Set this question in the text area
            st.session_state.user_query = question
            
    st.markdown("---")

    # Prepare context for Gemini (optional, but improves answers)
    context = "Here is a summary of the current simulated CrowdStrike alerts:\n\n"
    for alert in alerts_data:
        context += f"- ID: {alert['id']}, Title: {alert['title']}, Severity: {alert['severity']}\n"
    context += "\n---\n"

    # Initialize the query variable in session state if it doesn't exist
    if 'user_query' not in st.session_state:
        st.session_state.user_query = ""
        
    # User query input with the current value from session state
    user_query = st.text_area("Your Question:", height=100, value=st.session_state.user_query)

    # Use columns for the chat action buttons
    col1, col2 = st.columns([1, 1])
    ask_button = col1.button("Ask Gemini")
    clear_button = col2.button("Clear Chat")
    
    # Handle clear button click
    if clear_button:
        st.session_state.chat_history = []
        st.session_state.user_query = ""
        st.rerun()  # Use st.rerun() instead of experimental_rerun()
    
    # Handle ask button click
    if ask_button:
        if not user_query:
            st.warning("Please enter a question.")
        elif not gemini_available:
             st.error("Gemini AI is not configured or available.")
        else:
            # Add the query to chat history
            prompt = f"You are a helpful SOC assistant analyzing simulated CrowdStrike data.\n\n{context}\n\nBased on the context above and general security knowledge, answer the following question: {user_query}"
            
            with st.spinner("Thinking..."):
                response = ask_gemini(prompt, st.session_state.chat_history)
            
            # Add to chat history
            st.session_state.chat_history.append({
                "question": user_query,
                "answer": response
            })
            
            # Clear the input area after submission
            st.session_state.user_query = ""
            
            # Rerun to refresh the page with the updated chat history
            st.rerun()  # Use st.rerun() instead of experimental_rerun()
    
    # Display chat history
    st.subheader("Chat History")
    chat_container = st.container()
    
    with chat_container:
        if not st.session_state.chat_history:
            st.info("No chat history yet. Ask a question to get started!")
        else:
            for i, entry in enumerate(st.session_state.chat_history):
                st.markdown(f"**You:** {entry['question']}")
                st.markdown(f"**Gemini:** {entry['answer']}")
                st.markdown("---")
    
    # Download chat history button
    if st.session_state.chat_history:
        st.markdown(download_chat_history(st.session_state.chat_history), unsafe_allow_html=True)

# --- Footer ---
st.markdown("---")
st.caption("Simulated Data | For Demonstration Purposes Only")