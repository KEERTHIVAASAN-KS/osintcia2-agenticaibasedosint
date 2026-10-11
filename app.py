import json
import re
import socket
import sqlite3
import hashlib
from datetime import datetime, timezone
from urllib.parse import urlparse

import networkx as nx
import pandas as pd
import requests
import streamlit as st
from bs4 import BeautifulSoup

import ollama
import dns.resolver
import json

APP_TITLE = "Agentic AI-Based OSINT Investigation System"
DB_PATH = "evidence.db"
HEADERS = {
    "User-Agent": "AcademicOSINTResearch/1.0 (passive public-source research)"
}
TIMEOUT = 12


class EvidenceRepository:
    """Stores source observations and agent findings in SQLite."""

    def __init__(self, db_path=DB_PATH):
        self.db_path = db_path
        self._initialize()

    def connect(self):
        return sqlite3.connect(self.db_path)

    def _initialize(self):
        with self.connect() as con:
            con.execute("""
                CREATE TABLE IF NOT EXISTS evidence (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    investigation_id TEXT NOT NULL,
                    agent TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    evidence_type TEXT NOT NULL,
                    value TEXT NOT NULL,
                    source_url TEXT NOT NULL,
                    observed_at TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    notes TEXT,
                    content_hash TEXT NOT NULL
                )
            """)
            con.execute("""
                CREATE TABLE IF NOT EXISTS investigations (
                    investigation_id TEXT PRIMARY KEY,
                    target TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
            """)

    def create_investigation(self, investigation_id, target):
        with self.connect() as con:
            con.execute(
                """INSERT OR REPLACE INTO investigations
                   (investigation_id, target, created_at)
                   VALUES (?, ?, ?)""",
                (investigation_id, target, utc_now())
            )

    def add(self, investigation_id, agent, subject, evidence_type,
            value, source_url, confidence=0.7, notes=""):
        value = str(value)
        fingerprint = hashlib.sha256(
            f"{source_url}|{subject}|{evidence_type}|{value}".encode("utf-8")
        ).hexdigest()

        with self.connect() as con:
            con.execute("""
                INSERT INTO evidence
                (investigation_id, agent, subject, evidence_type, value,
                 source_url, observed_at, confidence, notes, content_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                investigation_id, agent, subject, evidence_type, value,
                source_url, utc_now(), float(confidence), notes, fingerprint
            ))

    def get_evidence(self, investigation_id):
        with self.connect() as con:
            return pd.read_sql_query(
                """SELECT id, agent, subject, evidence_type, value,
                          source_url, observed_at, confidence, notes, content_hash
                   FROM evidence
                   WHERE investigation_id = ?
                   ORDER BY id""",
                con, params=(investigation_id,)
            )


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")



def normalize_domain(value):
    """Accept a domain or URL and return a normalized hostname."""
    value = value.strip()
    if not value:
        raise ValueError("Enter a domain name.")

    if "://" not in value:
        value = "https://" + value

    parsed = urlparse(value)
    host = (parsed.hostname or "").lower().strip(".")

    if not host or "." not in host:
        raise ValueError("Enter a valid public domain, such as example.com.")

    if len(host) > 253 or any(
        not re.fullmatch(r"[a-z0-9-]{1,63}", label)
        or label.startswith("-") or label.endswith("-")
        for label in host.split(".")
    ):
        raise ValueError("The domain format is invalid.")

    return host


def safe_get(url, params=None):
    """Read public information with a timeout and a clear user agent."""
    try:
        response = requests.get(
            url, params=params, headers=HEADERS, timeout=TIMEOUT
        )
        response.raise_for_status()
        return response, None
    except requests.RequestException as exc:
        return None, str(exc)



# AGENT 1: COLLECTION AGENT


class CollectionAgent:
    def __init__(self, repository):
        self.repo = repository

    def collect(self, investigation_id, domain):
        findings = []

        # Source 1: RDAP domain registration data
        rdap_url = f"https://rdap.org/domain/{domain}"
        response, error = safe_get(rdap_url)

        if response is not None:
            try:
                data = response.json()
                registrar = None
                for entity in data.get("entities", []):
                    roles = entity.get("roles", [])
                    if "registrar" in roles:
                        registrar = entity.get("handle") or entity.get("vcardArray")
                        break

                created = []
                for event in data.get("events", []):
                    if event.get("eventAction") in (
                        "registration", "registered", "creation"
                    ):
                        created.append(event.get("eventDate"))

                self.repo.add(
                    investigation_id, "Collection Agent", domain,
                    "domain_registration", json.dumps({
                        "ldhName": data.get("ldhName"),
                        "status": data.get("status", []),
                        "registrar": registrar,
                        "creation_events": created
                    }, ensure_ascii=False),
                    rdap_url, 0.9,
                    "Returned by the public RDAP endpoint; fields may be absent."
                )
                findings.append({
                    "type": "RDAP registration data",
                    "source": rdap_url,
                    "status": "Collected"
                })
            except (ValueError, TypeError) as exc:
                findings.append({
                    "type": "RDAP registration data",
                    "source": rdap_url,
                    "status": f"Could not parse response: {exc}"
                })
        else:
            findings.append({
                "type": "RDAP registration data",
                "source": rdap_url,
                "status": f"Unavailable: {error}"
            })

        # Source 2: Certificate Transparency (crt.sh)
        ct_url = "https://crt.sh/"
        response, error = safe_get(
            ct_url, params={"q": f"%.{domain}", "output": "json"}
        )

        if response is not None:
            try:
                rows = response.json()
                seen = set()
                subdomains = []

                for row in rows:
                    names = row.get("name_value", "")
                    for name in names.splitlines():
                        name = name.lower().strip().lstrip("*.")
                        if name == domain or name.endswith("." + domain):
                            if name not in seen:
                                seen.add(name)
                                subdomains.append(name)

                for subdomain in subdomains:
                    self.repo.add(
                        investigation_id, "Collection Agent", domain,
                        "certificate_hostname", subdomain, ct_url, 0.85,
                        "Hostname appeared in public Certificate Transparency data; "
                        "this does not prove the hostname is currently active."
                    )

                findings.append({
                    "type": "Certificate Transparency hostnames",
                    "source": ct_url,
                    "status": f"Collected {len(subdomains)} unique hostname(s)"
                })
            except (ValueError, TypeError) as exc:
                findings.append({
                    "type": "Certificate Transparency hostnames",
                    "source": ct_url,
                    "status": f"Could not parse response: {exc}"
                })
        else:
            findings.append({
                "type": "Certificate Transparency hostnames",
                "source": ct_url,
                "status": f"Unavailable: {error}"
            })

        # Source 3: DNS resolution via the operating system resolver
        dns_source = "system DNS resolver"
        try:
            answers = sorted({
                item[4][0] for item in socket.getaddrinfo(
                    domain, None, family=socket.AF_INET,
                    type=socket.SOCK_STREAM
                )
            })
            self.repo.add(
                investigation_id, "Collection Agent", domain,
                "dns_ipv4", json.dumps(answers), dns_source, 0.8,
                "Resolved using the machine's configured DNS resolver."
            )
            findings.append({
                "type": "DNS IPv4 resolution",
                "source": dns_source,
                "status": f"Found {len(answers)} IPv4 address(es)"
            })
        except socket.gaierror as exc:
            findings.append({
                "type": "DNS IPv4 resolution",
                "source": dns_source,
                "status": f"Unavailable: {exc}"
            })

        # Source 4: Read homepage metadata only
        homepage = f"https://{domain}/"
        response, error = safe_get(homepage)

        if response is None:
            homepage = f"http://{domain}/"
            response, error = safe_get(homepage)

        if response is not None:
            soup = BeautifulSoup(response.text[:1_000_000], "html.parser")
            title = soup.title.get_text(" ", strip=True) if soup.title else ""
            description_tag = soup.find(
                "meta", attrs={"name": re.compile("^description$", re.I)}
            )
            description = (
                description_tag.get("content", "").strip()
                if description_tag else ""
            )
            self.repo.add(
                investigation_id, "Collection Agent", domain,
                "website_metadata", json.dumps({
                    "final_url": response.url,
                    "http_status": response.status_code,
                    "title": title,
                    "description": description
                }, ensure_ascii=False),
                response.url, 0.8,
                "Public homepage metadata only; page content is untrusted input."
            )
            findings.append({
                "type": "Homepage metadata",
                "source": response.url,
                "status": "Collected"
            })
        else:
            findings.append({
                "type": "Homepage metadata",
                "source": f"https://{domain}/",
                "status": f"Unavailable: {error}"
            })

        return findings


# AGENT 2: VERIFICATION AGENT


class VerificationAgent:
    """Checks whether selected observations have corroborating records."""

    def __init__(self, repository):
        self.repo = repository

    def run(self, investigation_id):
        df = self.repo.get_evidence(investigation_id)
        if df.empty:
            return pd.DataFrame()

        results = []
        dns_rows = df[df["evidence_type"] == "dns_ipv4"]
        ct_rows = df[df["evidence_type"] == "certificate_hostname"]
        metadata_rows = df[df["evidence_type"] == "website_metadata"]

        for _, row in df.iterrows():
            if row["evidence_type"] == "certificate_hostname":
                hostname = row["value"]
                results.append({
                    "claim": f"Certificate data contains hostname {hostname}",
                    "verification": "Source observation",
                    "confidence": 0.85,
                    "explanation": (
                        "This confirms that the hostname was returned by the CT source, "
                        "not that it is currently online or owned by a particular person."
                    ),
                    "source": row["source_url"]
                })

        if not dns_rows.empty and not metadata_rows.empty:
            results.append({
                "claim": "The domain resolved in DNS and its homepage returned a response",
                "verification": "Corroborated by two different observation types",
                "confidence": 0.8,
                "explanation": (
                    "DNS resolution and an HTTP homepage response were observed. "
                    "This does not establish trustworthiness or maliciousness."
                ),
                "source": "DNS resolver + homepage metadata"
            })

        if dns_rows.empty:
            results.append({
                "claim": "IPv4 DNS resolution",
                "verification": "Not verified",
                "confidence": 0.0,
                "explanation": "No IPv4 DNS result was collected in this run.",
                "source": "system DNS resolver"
            })

        return pd.DataFrame(results)


# AGENT 3: ENTITY RESOLUTION AGENT

class EntityResolutionAgent:
    def __init__(self, repository):
        self.repo = repository

    def run(self, investigation_id, domain):
        df = self.repo.get_evidence(investigation_id)
        entities = [{
            "entity": domain,
            "entity_type": "domain",
            "source": "User-provided investigation target"
        }]

        if df.empty:
            return pd.DataFrame(entities)

        for _, row in df.iterrows():
            if row["evidence_type"] == "certificate_hostname":
                entities.append({
                    "entity": row["value"],
                    "entity_type": "hostname",
                    "source": row["source_url"]
                })

            elif row["evidence_type"] == "dns_ipv4":
                try:
                    for ip in json.loads(row["value"]):
                        entities.append({
                            "entity": ip,
                            "entity_type": "IPv4 address",
                            "source": row["source_url"]
                        })
                except (ValueError, TypeError):
                    pass

        result = pd.DataFrame(entities).drop_duplicates(
            subset=["entity", "entity_type"]
        )
        return result.reset_index(drop=True)


# AGENT 4: LINK ANALYSIS AGENT

class LinkAnalysisAgent:
    def __init__(self, repository):
        self.repo = repository

    def run(self, investigation_id, domain):
        df = self.repo.get_evidence(investigation_id)
        graph = nx.Graph()
        graph.add_node(domain, entity_type="domain")

        if df.empty:
            return graph, pd.DataFrame(columns=[
                "source_entity", "relationship", "target_entity", "evidence_source"
            ])

        links = []
        for _, row in df.iterrows():
            if row["evidence_type"] == "certificate_hostname":
                hostname = row["value"]
                graph.add_node(hostname, entity_type="hostname")
                graph.add_edge(domain, hostname, relation="listed_in_CT")
                links.append({
                    "source_entity": domain,
                    "relationship": "hostname observed in certificate data",
                    "target_entity": hostname,
                    "evidence_source": row["source_url"]
                })

            elif row["evidence_type"] == "dns_ipv4":
                try:
                    addresses = json.loads(row["value"])
                except (ValueError, TypeError):
                    addresses = []

                for ip in addresses:
                    graph.add_node(ip, entity_type="IPv4 address")
                    graph.add_edge(domain, ip, relation="resolved_to")
                    links.append({
                        "source_entity": domain,
                        "relationship": "resolved to IPv4 address",
                        "target_entity": ip,
                        "evidence_source": row["source_url"]
                    })

        return graph, pd.DataFrame(links)


# AGENT 5: RISK ASSESSMENT AGENT

class RiskAssessmentAgent:
    """
    Reports observable exposure/context indicators.
    It does not label a domain malicious based on these indicators alone.
    """

    def run(self, evidence_df, domain):
        indicators = []

        has_dns = (
            not evidence_df.empty
            and (evidence_df["evidence_type"] == "dns_ipv4").any()
        )
        has_homepage = (
            not evidence_df.empty
            and (evidence_df["evidence_type"] == "website_metadata").any()
        )
        ct_count = (
            int((evidence_df["evidence_type"] == "certificate_hostname").sum())
            if not evidence_df.empty else 0
        )

        indicators.append({
            "indicator": "IPv4 DNS result collected",
            "observation": "Yes" if has_dns else "No result collected",
            "interpretation": (
                "A DNS address was observed."
                if has_dns else
                "No IPv4 answer was collected; this may be caused by DNS configuration "
                "or an unavailable domain and is not inherently suspicious."
            ),
            "risk": "Informational"
        })

        indicators.append({
            "indicator": "Homepage metadata collected",
            "observation": "Yes" if has_homepage else "No",
            "interpretation": (
                "The public homepage responded and metadata was extracted."
                if has_homepage else
                "No homepage metadata was collected; this is not proof of maliciousness."
            ),
            "risk": "Informational"
        })

        indicators.append({
            "indicator": "Certificate Transparency hostnames",
            "observation": str(ct_count),
            "interpretation": (
                "Hostnames appeared in public certificate records. This can help map "
                "the domain's public footprint but does not imply risk by itself."
            ),
            "risk": "Informational"
        })

        return pd.DataFrame(indicators)


# AGENT 6: REPORTING AGENT

class ReportingAgent:
    def generate(self, domain, evidence_df, entities_df, links_df,
                 verification_df, risk_df):
        lines = [
            f"# OSINT Investigation Report: {domain}",
            "",
            f"- Generated (UTC): {utc_now()}",
            "- Scope: passive collection from public sources",
            "- Purpose: academic research",
            "",
            "## Executive Summary",
            f"- Evidence records collected: {len(evidence_df)}",
            f"- Entities identified: {len(entities_df)}",
            f"- Relationships recorded: {len(links_df)}",
            f"- Verification observations: {len(verification_df)}",
            "",
            "This report records observable public information. It does not determine "
            "that a domain or associated entity is malicious.",
            "",
            "## Entities",
        ]

        if entities_df.empty:
            lines.append("No entities were extracted.")
        else:
            for _, row in entities_df.iterrows():
                lines.append(
                    f"- **{row['entity']}** ({row['entity_type']}) — "
                    f"source: {row['source']}"
                )

        lines.extend(["", "## Relationships"])
        if links_df.empty:
            lines.append("No evidence-backed relationships were recorded.")
        else:
            for _, row in links_df.iterrows():
                lines.append(
                    f"- `{row['source_entity']}` — "
                    f"{row['relationship']} — `{row['target_entity']}` "
                    f"(source: {row['evidence_source']})"
                )

        lines.extend(["", "## Verification"])
        if verification_df.empty:
            lines.append("No verification observations were generated.")
        else:
            for _, row in verification_df.iterrows():
                lines.append(
                    f"- **{row['claim']}**: {row['verification']}. "
                    f"Confidence: {row['confidence']:.2f}. "
                    f"{row['explanation']} Source: {row['source']}"
                )

        lines.extend(["", "## Context / Risk Indicators"])
        for _, row in risk_df.iterrows():
            lines.append(
                f"- **{row['indicator']}**: {row['observation']} "
                f"({row['risk']}). {row['interpretation']}"
            )

        lines.extend([
            "",
            "## Evidence Records",
            "Every collected record includes a source reference, observation time, "
            "agent name, confidence value, and SHA-256 fingerprint of the stored fields.",
            "",
            "## Limitations",
            "- Public-source availability and rate limits may affect collection.",
            "- A source observation is not proof of ownership, identity, or malicious intent.",
            "- Confidence values are rule-based initial estimates, not statistically calibrated.",
            "- Retrieved web content is untrusted and must not be treated as instructions.",
            "- Human review is required before making consequential decisions.",
        ])

        return "\n".join(lines)



class AIInvestigationAgent:
    """
    AI agent that examines OSINT evidence,
    chooses approved passive checks, and explains findings.
    """

    MODEL = "llama3.2:1b"
    MAX_STEPS = 3

    def __init__(self, domain):
        self.domain = domain
        self.actions = []

    def run(self, evidence_df):
        domain = self.domain

        # Tool 1: Check robots.txt
        def check_robots_txt() -> str:
            """Check the target domain's robots.txt file."""
            import requests

            for scheme in ["https", "http"]:
                url = f"{scheme}://{domain}/robots.txt"

                try:
                    response = requests.get(
                        url,
                        headers=HEADERS,
                        timeout=TIMEOUT
                    )

                    result = {
                        "tool": "check_robots_txt",
                        "url": url,
                        "status": response.status_code,
                        "content": response.text[:1500]
                    }

                    self.actions.append(result)
                    return json.dumps(result)

                except requests.RequestException:
                    continue

            result = {
                "tool": "check_robots_txt",
                "result": "Could not retrieve robots.txt"
            }
            self.actions.append(result)
            return json.dumps(result)

        # Tool 2: Check security.txt
        def check_security_txt() -> str:
            """Look for the target domain's security.txt file."""
            import requests

            paths = [
                "/.well-known/security.txt",
                "/security.txt"
            ]

            for scheme in ["https", "http"]:
                for path in paths:
                    url = f"{scheme}://{domain}{path}"

                    try:
                        response = requests.get(
                            url,
                            headers=HEADERS,
                            timeout=TIMEOUT
                        )

                        if response.status_code == 200:
                            result = {
                                "tool": "check_security_txt",
                                "url": url,
                                "content": response.text[:1500]
                            }
                            self.actions.append(result)
                            return json.dumps(result)

                    except requests.RequestException:
                        continue

            result = {
                "tool": "check_security_txt",
                "result": "No accessible security.txt file found"
            }
            self.actions.append(result)
            return json.dumps(result)

        # Tool 3: Check DNS MX records
        def check_mx_records() -> str:
            """Retrieve MX records for the target domain."""
            try:
                answers = dns.resolver.resolve(
                    domain, "MX", lifetime=5
                )

                records = sorted(
                    str(answer.exchange).rstrip(".")
                    for answer in answers
                )

                result = {
                    "tool": "check_mx_records",
                    "records": records
                }

            except Exception as exc:
                result = {
                    "tool": "check_mx_records",
                    "result": f"Lookup unsuccessful: {exc}"
                }

            self.actions.append(result)
            return json.dumps(result)

        available_tools = {
            "check_robots_txt": check_robots_txt,
            "check_security_txt": check_security_txt,
            "check_mx_records": check_mx_records
        }

        evidence_text = (
            evidence_df.head(30).to_string(index=False)
            if not evidence_df.empty
            else "No existing evidence was collected."
        )

        messages = [
            {
                "role": "system",
                "content": f"""
You are an AI OSINT investigation agent.

Target domain: {domain}

Your task:
1. Examine the supplied evidence.
2. Decide which additional passive check would be useful.
3. Use only the tools provided to you.
4. Review the tool results before making conclusions.
5. Stop when sufficient evidence is available.

You may perform at most {self.MAX_STEPS} tool calls.

Do not attempt login, exploitation, scanning, or attacks.
Do not treat missing data as proof of malicious activity.
Distinguish observed facts from possible interpretations.
Do not invent evidence.
"""
            },
            {
                "role": "user",
                "content": (
                    "Analyze this existing OSINT evidence:\n\n"
                    + evidence_text
                    + "\n\nChoose a useful next check if needed, "
                    "then summarize your findings."
                )
            }
        ]

        analysis = ""

        try:
            for step in range(self.MAX_STEPS + 1):
                response = ollama.chat(
                    model=self.MODEL,
                    messages=messages,
                    tools=list(available_tools.values())
                )

                messages.append(response.message)
                tool_calls = response.message.tool_calls or []

                if not tool_calls:
                    analysis = response.message.content
                    break

                # Do not allow more than MAX_STEPS tool calls.
                remaining = self.MAX_STEPS - len(self.actions)

                if remaining <= 0:
                    messages.append({
                        "role": "user",
                        "content": (
                            "The tool-call limit has been reached. "
                            "Summarize the evidence already available."
                        )
                    })
                    continue

                for call in tool_calls[:remaining]:
                    tool_name = call.function.name
                    tool_function = available_tools.get(tool_name)

                    if tool_function is None:
                        result = "Tool not permitted."
                    else:
                        try:
                            result = tool_function()
                        except Exception as exc:
                            result = f"Tool failed: {exc}"

                    messages.append({
                        "role": "tool",
                        "tool_name": tool_name,
                        "content": str(result)
                    })

            if not analysis:
                analysis = (
                    "The AI reached its investigation limit. "
                    "Review the available tool results below."
                )

        except Exception as exc:
            analysis = (
                f"AI investigation could not complete: {exc}. "
                "Check that Ollama is running and the model exists."
            )

        return {
            "analysis": analysis,
            "actions": self.actions
        }




# STREAMLIT USER INTERFACE

st.set_page_config(page_title=APP_TITLE, layout="wide")

st.title("Agentic AI-Based OSINT Investigation System")

st.write(
    "A prototype for passive public-source collection, "
    "evidence tracking, entity resolution, link analysis, AI-assisted "
    "investigation, and reporting."
)

repository = EvidenceRepository()

with st.form("investigation_form"):
    target_input = st.text_input(
        "Target domain",
        placeholder="example.com",
        help="Enter a domain you are permitted to investigate."
    )
    submitted = st.form_submit_button("Run OSINT Investigation")


# RUN THE INVESTIGATION

if submitted:
    try:
        domain = normalize_domain(target_input)

        investigation_id = (
            f"{domain}-"
            f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
        )

        repository.create_investigation(investigation_id, domain)

        # Agent 1: Collection
        with st.spinner(
            "Collection Agent is gathering public-source observations..."
        ):
            collection_agent = CollectionAgent(repository)
            collection_status = collection_agent.collect(
                investigation_id, domain
            )

        evidence_df = repository.get_evidence(investigation_id)

        # Agent 7: AI Investigation
        with st.spinner("AI Investigation Agent is analyzing evidence..."):
            ai_agent = AIInvestigationAgent(domain)
            ai_result = ai_agent.run(evidence_df)

        # Refresh evidence to include AI tool observations.
        evidence_df = repository.get_evidence(investigation_id)

        # Agents 2-6: Process evidence
        with st.spinner(
            "Specialized agents are processing collected evidence..."
        ):
            verification_df = VerificationAgent(repository).run(
                investigation_id
            )

            entities_df = EntityResolutionAgent(repository).run(
                investigation_id, domain
            )

            graph, links_df = LinkAnalysisAgent(repository).run(
                investigation_id, domain
            )

            risk_df = RiskAssessmentAgent().run(
                evidence_df, domain
            )

            report = ReportingAgent().generate(
                domain,
                evidence_df,
                entities_df,
                links_df,
                verification_df,
                risk_df
            )

        # Include AI findings in the report.
        report += "\n\n## AI Investigation Findings\n\n"
        report += ai_result["analysis"]

        report += "\n\n## AI Investigation Actions\n\n"
        report += "```json\n"
        report += json.dumps(
            ai_result["actions"],
            indent=2,
            ensure_ascii=False
        )
        report += "\n```\n"

        # Save results for the Streamlit tabs.
        st.session_state["last_result"] = {
            "investigation_id": investigation_id,
            "domain": domain,
            "collection_status": collection_status,
            "evidence": evidence_df,
            "verification": verification_df,
            "entities": entities_df,
            "links": links_df,
            "graph": graph,
            "risk": risk_df,
            "report": report,
            "ai_analysis": ai_result["analysis"],
            "ai_actions": ai_result["actions"],
        }

    except ValueError as exc:
        st.error(str(exc))

    except Exception as exc:
        st.error(f"Investigation failed: {exc}")


# DISPLAY RESULTS

result = st.session_state.get("last_result")

if result:
    st.success(f"Investigation completed for {result['domain']}")
    st.caption(f"Investigation ID: {result['investigation_id']}")

    tabs = st.tabs([
        "Overview",
        "Evidence",
        "Verification",
        "Entities & Links",
        "Risk Context",
        "Report",
        "AI Investigation"
    ])

    # TAB 1: OVERVIEW
    with tabs[0]:
        col1, col2, col3 = st.columns(3)

        col1.metric("Evidence records", len(result["evidence"]))
        col2.metric("Entities", len(result["entities"]))
        col3.metric("Relationships", len(result["links"]))

        st.subheader("Collection status")
        st.dataframe(
            pd.DataFrame(result["collection_status"]),
            use_container_width=True
        )

    # TAB 2: EVIDENCE
    with tabs[1]:
        st.subheader("Evidence Repository")

        st.dataframe(
            result["evidence"],
            use_container_width=True
        )

        st.caption(
            "SHA-256 fingerprints identify stored evidence fields; "
            "they do not independently prove source authenticity."
        )

        st.download_button(
            "Download evidence as CSV",
            data=result["evidence"].to_csv(index=False).encode("utf-8"),
            file_name="osint_evidence.csv",
            mime="text/csv"
        )

    # TAB 3: VERIFICATION
   
    with tabs[2]:
        st.subheader("Verification Observations")

        if result["verification"].empty:
            st.info("No verification observations were generated.")
        else:
            st.dataframe(
                result["verification"],
                use_container_width=True
            )

    # TAB 4: ENTITIES AND LINKS
    with tabs[3]:
        st.subheader("Extracted Entities")

        st.dataframe(
            result["entities"],
            use_container_width=True
        )

        st.subheader("Evidence-Backed Relationships")

        if result["links"].empty:
            st.info("No relationships were found in the collected records.")
        else:
            st.dataframe(
                result["links"],
                use_container_width=True
            )

        graph = result["graph"]

        if graph.number_of_edges() > 0:
            try:
                import matplotlib.pyplot as plt

                fig, ax = plt.subplots(figsize=(10, 6))
                pos = nx.spring_layout(graph, seed=42)

                nx.draw_networkx(
                    graph,
                    pos=pos,
                    ax=ax,
                    with_labels=True,
                    node_size=1800,
                    font_size=8
                )

                ax.axis("off")
                st.pyplot(fig)
                plt.close(fig)

            except ImportError:
                st.info(
                    "Install matplotlib to display the graph: "
                    "pip install matplotlib"
                )

    # TAB 5: RISK CONTEXT
    with tabs[4]:
        st.subheader("Risk Context")

        st.dataframe(
            result["risk"],
            use_container_width=True
        )

        st.caption(
            "These are contextual observations, not a verdict that "
            "the target is malicious."
        )

    # TAB 6: REPORT
    with tabs[5]:
        st.subheader("Investigation Report")

        st.markdown(result["report"])

        st.download_button(
            "Download Investigation Report",
            data=result["report"].encode("utf-8"),
            file_name=f"{result['domain']}_osint_report.md",
            mime="text/markdown"
        )

    # TAB 7: AI INVESTIGATION
    with tabs[6]:
        st.subheader("AI Investigation Findings")

        st.markdown(result["ai_analysis"])

        st.divider()

        st.subheader("Additional Checks Requested by AI")

        ai_actions = result["ai_actions"]

        if ai_actions:
            for index, action in enumerate(ai_actions, start=1):
                with st.expander(
                    f"Check {index}: {action['tool']}",
                    expanded=False
                ):
                    st.json(action)
        else:
            st.info(
                "The AI did not perform any additional checks. "
                "Review its analysis and the collected evidence."
            )

        st.caption(
            "AI-generated findings may be incomplete or incorrect. "
            "Verify important conclusions against the recorded evidence."
        )