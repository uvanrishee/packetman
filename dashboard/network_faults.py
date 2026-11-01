"""
Network Faults & Operational Degradation view (§8.4).
Displays evidence-backed network fault findings (retransmissions, resets, incomplete handshakes,
unusual delay / latency, DNS failures, ARP conflicts, MTU bottlenecks).
"""

from __future__ import annotations

import streamlit as st

from analysis.confidence import format_confidence_label
from analysis.severity import get_severity_badge_color
from dashboard.session import get_current_analysis, set_selected_packet


def render_network_faults_page() -> None:
    st.title("🔴 Network Faults & Operational Issues")
    st.caption("Detailed breakdown of observed transport degradation, routing bottlenecks, and protocol timeouts.")

    res = get_current_analysis()
    if not res:
        st.info("No active capture analysis found. Please upload or select a capture on the Overview page first.")
        return

    faults = [f for f in res.findings if f.category == "NETWORK_FAULT"]

    # Metric summary row
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.metric("Total Network Faults", len(faults))
    with c2:
        high_cnt = sum(1 for f in faults if f.severity in ("HIGH", "CRITICAL"))
        st.metric("High/Critical Severity", high_cnt)
    with c3:
        types_cnt = len(set(f.type for f in faults))
        st.metric("Fault Categories", types_cnt)
    with c4:
        affected = set()
        for f in faults:
            affected.update(f.affected_hosts)
        st.metric("Affected Hosts", len(affected))

    st.divider()

    if not faults:
        st.success("✅ No operational network faults detected in this capture window.")
        return

    # Filter controls
    col_filter_type, col_filter_sev = st.columns(2)
    with col_filter_type:
        all_types = ["All Types"] + sorted(list(set(f.type for f in faults)))
        sel_type = st.selectbox("Filter by Fault Type", all_types, index=0)
    with col_filter_sev:
        all_sevs = ["All Severities", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        sel_sev = st.selectbox("Filter by Severity", all_sevs, index=0)

    filtered = faults
    if sel_type != "All Types":
        filtered = [f for f in filtered if f.type == sel_type]
    if sel_sev != "All Severities":
        filtered = [f for f in filtered if f.severity == sel_sev]

    st.markdown(f"**Showing {len(filtered)} of {len(faults)} Network Fault Finding(s)**")

    for f in filtered:
        _render_fault_card(f)


def _render_fault_card(f) -> None:
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
        st.markdown(f"**Likely Cause:**  \n{f.likely_cause}")

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
                if st.button(f"Inspect Packet #{primary_pkt} in Packet Explorer", key=f"btn_fault_{f.finding_id}"):
                    set_selected_packet(primary_pkt)
                    st.info(
                        f"Packet **#{primary_pkt}** selected as the inspection target. "
                        "Navigate to **Packet Explorer** in the left sidebar to view the full field breakdown."
                    )

            st.markdown("**Explicit PCAP Limitations:**")
            for lim in f.limitations:
                st.markdown(f"- *{lim}*")
