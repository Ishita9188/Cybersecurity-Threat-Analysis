import streamlit as st
import pandas as pd
import plotly.express as px
import matplotlib.pyplot as plt
st.set_page_config(page_title="CyberShield Dashboard",page_icon="🛡️",layout="wide")
st.markdown("""
<style>
.main{
    background-color:#0E1117;
}
h1,h2,h3{
    color:#00E5FF;
}
.stMetric{
    background:#1B263B;
    border-radius:10px;
    padding:8px;
}
footer{visibility:hidden;}
</style>
""", unsafe_allow_html=True)
st.title("🛡 CyberShield Threat Analytics Dashboard")
st.markdown("Monitor and analyze cybersecurity attacks using interactive visualizations.")
@st.cache_data
def load_data():
    df = pd.read_csv("cybersecurity_attacks.csv")
    df.columns = df.columns.str.strip()
    return df
df = load_data()
st.sidebar.header("⚙ Filters")
severity = st.sidebar.multiselect(
    "Severity Level",
    sorted(df["Severity Level"].dropna().unique()),
    default=sorted(df["Severity Level"].dropna().unique())
)
attack = st.sidebar.multiselect(
    "Attack Type",
    sorted(df["Attack Type"].dropna().unique()),
    default=sorted(df["Attack Type"].dropna().unique())
)
segment = st.sidebar.selectbox(
    "Network Segment",
    ["All"] + list(sorted(df["Network Segment"].dropna().unique()))
)
score = st.sidebar.slider(
    "Anomaly Score",
    float(df["Anomaly Scores"].min()),
    float(df["Anomaly Scores"].max()),
    (float(df["Anomaly Scores"].min()),
     float(df["Anomaly Scores"].max()))
)
filtered = df[
    (df["Severity Level"].isin(severity)) &
    (df["Attack Type"].isin(attack)) &
    (df["Anomaly Scores"].between(score[0], score[1]))
]
if segment != "All":
    filtered = filtered[filtered["Network Segment"] == segment]
st.header("📊 Security Overview")
c1, c2, c3, c4 = st.columns(4)
c1.metric("Total Incidents", len(filtered))
c2.metric(
    "Unique Attack Types",
    filtered["Attack Type"].nunique()
)
c3.metric(
    "Average Anomaly Score",
    round(filtered["Anomaly Scores"].mean(),2)
)
c4.metric(
    "Critical Alerts",
    len(filtered[filtered["Severity Level"]=="High"])
)
with st.expander("ℹ About this Dashboard"):
    st.write("""
This dashboard provides an overview of cybersecurity incidents.
Features included:
- Interactive filters
- KPI metrics
- Data visualization
- Threat exploration
- Downloadable filtered dataset
""")
st.header("📁 Filtered Incident Records")
st.dataframe(
    filtered,
    use_container_width=True,
    height=350
)
tab1, tab2 = st.tabs(["📈 Charts", "📋 Summary"])
with tab1:
    col1, col2 = st.columns(2)
    with col1:
        st.subheader("Attack Type Distribution")
        attack_chart = filtered["Attack Type"].value_counts().reset_index()
        attack_chart.columns = ["Attack Type", "Count"]
        fig = px.bar(
            attack_chart,
            x="Attack Type",
            y="Count",
            color="Attack Type",
            title="Attack Types"
        )
        st.plotly_chart(fig, use_container_width=True)
    with col2:
        st.subheader("Severity Level Distribution")
        pie = px.pie(
            filtered,
            names="Severity Level",
            title="Severity Levels",
            hole=0.4
        )
        st.plotly_chart(pie, use_container_width=True)
    col3, col4 = st.columns(2)
    with col3:
        st.subheader("Anomaly Score Distribution")
        fig2, ax = plt.subplots(figsize=(6,4))
        ax.hist(filtered["Anomaly Scores"], bins=20)
        ax.set_xlabel("Anomaly Score")
        ax.set_ylabel("Frequency")
        st.pyplot(fig2)
    with col4:
        st.subheader("Packet Length vs Anomaly Score")
        scatter = px.scatter(
            filtered,
            x="Packet Length",
            y="Anomaly Scores",
            color="Severity Level",
            hover_data=["Attack Type"],
            title="Threat Analysis"
        )
        st.plotly_chart(scatter, use_container_width=True)
with tab2:
    st.subheader("Summary Statistics")
    summary = pd.DataFrame({
        "Metric":[
            "Total Records",
            "Average Packet Length",
            "Average Anomaly Score",
            "Unique Protocols",
            "Unique Attack Types"
        ],
        "Value":[
            len(filtered),
            round(filtered["Packet Length"].mean(),2),
            round(filtered["Anomaly Scores"].mean(),2),
            filtered["Protocol"].nunique(),
            filtered["Attack Type"].nunique()
        ]
    })
    st.table(summary)
    st.download_button(
        "⬇ Download Filtered CSV",
        filtered.to_csv(index=False),
        file_name="filtered_cybersecurity_report.csv",
        mime="text/csv"
    )
st.success("Dashboard Loaded Successfully")
st.markdown(
"""
<center>
Developed using <b>Streamlit</b> | Data Visualization using <b>Plotly</b> & <b>Matplotlib</b>
</center>
""",
unsafe_allow_html=True
)