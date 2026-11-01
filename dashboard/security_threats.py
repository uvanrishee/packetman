"""
Security Threats & Suspicious Behavior view (§8.5).
Displays evidence-backed detections of reconnaissance scans, sweep activities,
ARP spoofing indicators, rogue DHCP servers, and anomalous protocol behaviors.
"""

from __future__ import annotations

import streamlit as st

from analysis.confidence import format_confidence_label
from analysis.severity import get_severity_badge_color
from dashboard.session import get_current_analysis, set_selected_packet


def render_security_threats_page() -> None:
    st.title("⚠️ Security Threats & Suspicious Behavior")
    st.caption("Evidence-backed detections of reconnaissance scans, anomalous infrastructure claims, and potential attacks.")

    res = get_current_analysis()
    if not res:
        st.info("No active capture analysis found. Please upload or select a capture on the Overview page first.")
        return

    threats = [f for f in res.findings if f.category == "SECURITY"]

    # Metric summary row
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.metric("Total Security Threats", len(threats))
    with c2:
        high_cnt = sum(1 for f in threats if f.severity in ("HIGH", "CRITICAL"))
        st.metric("High/Critical Severity", high_cnt)
    with c3:
        types_cnt = len(set(f.type for f in threats))
        st.metric("Threat Types", types_cnt)
    with c4:
        affected = set()
        for f in threats:
            affected.update(f.affected_hosts)
        st.metric("Involved Hosts", len(affected))

    st.divider()

    if not threats:
        st.success("✅ No suspicious attack patterns or reconnaissance sweeps detected in this capture.")
        return

    # Filter controls
    col_filter_type, col_filter_sev = st.columns(2)
    with col_filter_type:
        all_types = ["All Types"] + sorted(list(set(f.type for f in threats)))
        sel_type = st.selectbox("Filter by Threat Type", all_types, index=0)
    with col_filter_sev:
        all_sevs = ["All Severities", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        sel_sev = st.selectbox("Filter by Threat Severity", all_sevs, index=0)

    filtered = threats
    if sel_type != "All Types":
        filtered = [f for f in filtered if f.type == sel_type]
    if sel_sev != "All Severities":
        filtered = [f for f in filtered if f.severity == sel_sev]

    st.markdown(f"**Showing {len(filtered)} of {len(threats)} Security Threat Finding(s)**")

    for f in filtered:
        _render_threat_card(f)


def _render_threat_card(f) -> None:
    badge_color = get_severity_badge_color(f.severity)
    conf_label = format_confidence_label(f.confidence)

    with st.container(border=True):
        col1, col2, col3 = st.columns([3, 1, 1])
        with col1:
            st.markdown(f"### {f.title}")
            st.caption(f"ID: `{f.finding_id}` | Type: `{f.type}` | Classification: `{f.classification}`")
        with col2:
            st.markdown(
                f"<div style='background-color:{badge_color};color:white;padding:4px 8px;border-radius:4px;text-align:center;font-weight:bold;'>{f.severity}</div>",
                unsafe_allow_html=True
            )
        with col3:
            st.markdown(
                f"<div style='background-color:#eceff1;color:#37474f;padding:4px 8px;border-radius:4px;text-align:center;font-size:0.85em;'>{conf_label}</div>",
                unsafe_allow_html=True
            )

        st.markdown(f"**Observed Facts / Condition:**  \n{f.reason}")
        st.markdown(f"**Likely Threat Cause:**  \n{f.likely_cause}")

        st.markdown("**Alternative Benign Explanations:**")
        for alt in f.alternative_explanations:
            st.markdown(f"- {alt}")

        st.markdown(f"**Recommended Actionable Steps:**  \n{f.recommendation}")

        with st.expander("Technical Evidence & PCAP Limitations"):
            st.markdown(f"**Endpoints:** `{f.source_ip or 'Any'}` → `{f.destination_ip or 'Any'}`")
            st.markdown(f"**Measured Metrics:** `{f.metrics}`")
            st.markdown(f"**Supporting Packet Numbers:** `{', '.join(map(str, f.evidence_packets))}`")

            if f.evidence_packets:
                primary_pkt = f.evidence_packets[0]
                if st.button(f"Inspect Packet #{primary_pkt} in Packet Explorer", key=f"btn_threat_{f.finding_id}"):
                    set_selected_packet(primary_pkt)
                    st.info(
                        f"Packet **#{primary_pkt}** selected as the inspection target. "
                        "Navigate to **Packet Explorer** in the left sidebar to view the full field breakdown."
                    )

            st.markdown("**Explicit PCAP Limitations:**")
            for lim in f.limitations:
                st.markdown(f"- *{lim}*")
