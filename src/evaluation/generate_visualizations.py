"""
Pure Python Vector Graphics (SVG) Generator for EDA and Benchmark Visualizations.
Fulfills Section 12 (Data & EDA): 3 labelled visualizations without external C++ DLL dependencies.
Produces crisp, scalable SVG vector charts:
- Fig 1: Corpus Class & Channel Distribution
- Fig 2: Campaign Groups & Holdout Separation
- Fig 3: Model Benchmark Comparison (Generalization Gap)
"""

import json
import os


def generate_svg_visualizations():
    os.makedirs("evidence/eda_figures", exist_ok=True)

    with open("data/corpus_manifest.json", "r", encoding="utf-8") as f:
        manifest = json.load(f)
    with open("evidence/model_benchmark_results.json", "r", encoding="utf-8") as f:
        bench = json.load(f)

    # -------------------------------------------------------------
    # Figure 1: Corpus Class & Channel Distribution
    # -------------------------------------------------------------
    phish_email, phish_sms = 0, 0
    legit_email, legit_sms = 0, 0

    for c_name, c_data in manifest["campaign_summary"].items():
        if c_data["label"] == "phishing":
            if c_data["channel"] == "email":
                phish_email += c_data["count"]
            else:
                phish_sms += c_data["count"]
        else:
            if c_data["channel"] == "email":
                legit_email += c_data["count"]
            else:
                legit_sms += c_data["count"]

    fig1_svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="650" height="360" viewBox="0 0 650 360" style="background:#0f172a; font-family:sans-serif;">
  <text x="325" y="32" fill="#f8fafc" font-size="16" font-weight="bold" text-anchor="middle">Figure 1: Corpus Class &amp; Channel Distribution (EDA)</text>
  <text x="325" y="52" fill="#94a3b8" font-size="12" text-anchor="middle">Total Curated Dataset: {manifest['total_records']} messages across 13 campaigns</text>

  <!-- Y Axis Grid & Labels -->
  <line x1="80" y1="270" x2="580" y2="270" stroke="#334155" stroke-width="1"/>
  <line x1="80" y1="210" x2="580" y2="210" stroke="#334155" stroke-dasharray="4" stroke-width="1"/>
  <line x1="80" y1="150" x2="580" y2="150" stroke="#334155" stroke-dasharray="4" stroke-width="1"/>
  <line x1="80" y1="90" x2="580" y2="90" stroke="#334155" stroke-dasharray="4" stroke-width="1"/>

  <text x="70" y="274" fill="#94a3b8" font-size="11" text-anchor="end">0</text>
  <text x="70" y="214" fill="#94a3b8" font-size="11" text-anchor="end">100</text>
  <text x="70" y="154" fill="#94a3b8" font-size="11" text-anchor="end">200</text>
  <text x="70" y="94" fill="#94a3b8" font-size="11" text-anchor="end">300</text>

  <!-- Phishing Group (x=140, 210) -->
  <rect x="140" y="{270 - phish_email*0.6}" width="55" height="{phish_email*0.6}" fill="#38bdf8" rx="4"/>
  <text x="167" y="{260 - phish_email*0.6}" fill="#f8fafc" font-size="11" font-weight="bold" text-anchor="middle">{phish_email}</text>

  <rect x="205" y="{270 - phish_sms*0.6}" width="55" height="{phish_sms*0.6}" fill="#10b981" rx="4"/>
  <text x="232" y="{260 - phish_sms*0.6}" fill="#f8fafc" font-size="11" font-weight="bold" text-anchor="middle">{phish_sms}</text>
  <text x="200" y="295" fill="#f8fafc" font-size="13" font-weight="bold" text-anchor="middle">Phishing (n={phish_email+phish_sms})</text>

  <!-- Legitimate Group (x=380, 445) -->
  <rect x="380" y="{270 - legit_email*0.6}" width="55" height="{legit_email*0.6}" fill="#38bdf8" rx="4"/>
  <text x="407" y="{260 - legit_email*0.6}" fill="#f8fafc" font-size="11" font-weight="bold" text-anchor="middle">{legit_email}</text>

  <rect x="445" y="{270 - legit_sms*0.6}" width="55" height="{legit_sms*0.6}" fill="#10b981" rx="4"/>
  <text x="472" y="{260 - legit_sms*0.6}" fill="#f8fafc" font-size="11" font-weight="bold" text-anchor="middle">{legit_sms}</text>
  <text x="440" y="295" fill="#f8fafc" font-size="13" font-weight="bold" text-anchor="middle">Legitimate (n={legit_email+legit_sms})</text>

  <!-- Legend -->
  <rect x="230" y="325" width="14" height="14" fill="#38bdf8" rx="2"/>
  <text x="250" y="337" fill="#f8fafc" font-size="12">Email Channel</text>
  <rect x="360" y="325" width="14" height="14" fill="#10b981" rx="2"/>
  <text x="380" y="337" fill="#f8fafc" font-size="12">SMS Channel</text>
</svg>"""

    with open("evidence/eda_figures/fig1_corpus_distribution.svg", "w", encoding="utf-8") as f:
        f.write(fig1_svg)
    print("Saved evidence/eda_figures/fig1_corpus_distribution.svg")

    # -------------------------------------------------------------
    # Figure 2: Campaign Groups & Holdout Separation (FR-03)
    # -------------------------------------------------------------
    campaigns = list(manifest["campaign_summary"].keys())
    fig2_svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="720" height="420" viewBox="0 0 720 420" style="background:#0f172a; font-family:sans-serif;">
  <text x="360" y="28" fill="#f8fafc" font-size="15" font-weight="bold" text-anchor="middle">Figure 2: Campaign Groups &amp; Zero-Leakage Holdout Separation (FR-03)</text>
  <text x="360" y="46" fill="#94a3b8" font-size="11.5" text-anchor="middle">Blue = Training Campaigns | Orange = Strictly Unseen Holdout Campaigns</text>
"""
    y_start = 70
    for idx, c in enumerate(campaigns):
        info = manifest["campaign_summary"][c]
        count = info["count"]
        is_hold = info["is_holdout"]
        color = "#f59e0b" if is_hold else "#38bdf8"
        bar_len = int(count * 5.0)
        clean_name = c.replace("phish_", "").replace("legit_", "")

        fig2_svg += f"""
  <text x="260" y="{y_start + 16}" fill="#cbd5e1" font-size="11" text-anchor="end">{clean_name} ({info['channel']})</text>
  <rect x="270" y="{y_start + 4}" width="{bar_len}" height="15" fill="{color}" rx="3"/>
  <text x="{278 + bar_len}" y="{y_start + 16}" fill="#f8fafc" font-size="10.5" font-weight="bold">{count}</text>"""
        y_start += 25

    fig2_svg += "\n</svg>"
    with open("evidence/eda_figures/fig2_campaign_partitions.svg", "w", encoding="utf-8") as f:
        f.write(fig2_svg)
    print("Saved evidence/eda_figures/fig2_campaign_partitions.svg")

    # -------------------------------------------------------------
    # Figure 3: Benchmark Model Comparison (Generalization Gap)
    # -------------------------------------------------------------
    models = list(bench["models"].keys())
    fig3_svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="700" height="380" viewBox="0 0 700 380" style="background:#0f172a; font-family:sans-serif;">
  <text x="350" y="30" fill="#f8fafc" font-size="16" font-weight="bold" text-anchor="middle">Figure 3: Model Generalization Gap on Unfamiliar Holdout Campaigns (FR-02, FR-03)</text>
  <text x="350" y="50" fill="#94a3b8" font-size="12" text-anchor="middle">Comparing In-Distribution Validation vs Out-of-Distribution Unseen Holdout Accuracy</text>

  <!-- Y Axis Grid -->
  <line x1="80" y1="280" x2="640" y2="280" stroke="#334155" stroke-width="1"/>
  <line x1="80" y1="225" x2="640" y2="225" stroke="#334155" stroke-dasharray="4" stroke-width="1"/>
  <line x1="80" y1="170" x2="640" y2="170" stroke="#334155" stroke-dasharray="4" stroke-width="1"/>
  <line x1="80" y1="115" x2="640" y2="115" stroke="#334155" stroke-dasharray="4" stroke-width="1"/>
  <line x1="80" y1="60" x2="640" y2="60" stroke="#334155" stroke-dasharray="4" stroke-width="1"/>

  <text x="70" y="284" fill="#94a3b8" font-size="11" text-anchor="end">0%</text>
  <text x="70" y="229" fill="#94a3b8" font-size="11" text-anchor="end">25%</text>
  <text x="70" y="174" fill="#94a3b8" font-size="11" text-anchor="end">50%</text>
  <text x="70" y="119" fill="#94a3b8" font-size="11" text-anchor="end">75%</text>
  <text x="70" y="64" fill="#94a3b8" font-size="11" text-anchor="end">100%</text>
"""
    x_positions = [130, 310, 490]
    for idx, m in enumerate(models):
        val_acc = bench["models"][m]["validation_in_distribution"]["accuracy"] * 100
        hold_acc = bench["models"][m]["holdout_out_of_distribution"]["accuracy"] * 100
        h_val = val_acc * 2.2
        h_hold = hold_acc * 2.2
        xp = x_positions[idx]

        fig3_svg += f"""
  <!-- {m} -->
  <rect x="{xp}" y="{280 - h_val}" width="50" height="{h_val}" fill="#818cf8" rx="4"/>
  <text x="{xp + 25}" y="{270 - h_val}" fill="#f8fafc" font-size="10.5" font-weight="bold" text-anchor="middle">{val_acc:.1f}%</text>

  <rect x="{xp + 55}" y="{280 - h_hold}" width="50" height="{h_hold}" fill="#f59e0b" rx="4"/>
  <text x="{xp + 80}" y="{270 - h_hold}" fill="#f8fafc" font-size="10.5" font-weight="bold" text-anchor="middle">{hold_acc:.1f}%</text>

  <text x="{xp + 52}" y="305" fill="#f8fafc" font-size="12" font-weight="bold" text-anchor="middle">{m.split(' ')[0]}</text>"""

    fig3_svg += """
  <!-- Legend -->
  <rect x="210" y="340" width="14" height="14" fill="#818cf8" rx="2"/>
  <text x="230" y="352" fill="#f8fafc" font-size="12">In-Distribution Validation Acc</text>
  <rect x="420" y="340" width="14" height="14" fill="#f59e0b" rx="2"/>
  <text x="440" y="352" fill="#f8fafc" font-size="12">Out-of-Distribution Holdout Acc</text>
</svg>"""

    with open("evidence/eda_figures/fig3_generalization_gap.svg", "w", encoding="utf-8") as f:
        f.write(fig3_svg)
    print("Saved evidence/eda_figures/fig3_generalization_gap.svg")


if __name__ == "__main__":
    generate_svg_visualizations()
