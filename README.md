# Intrusion-Detection-Project

A machine learning system that classifies network connections as normal traffic or one of four attack types — DoS, Probe, R2L, or U2R — with a focus on handling severe class imbalance and providing explainable predictions.

**🔗 Live Demo:** [https://intrusion-detection-project-ez39lgthrt5ivjb3euazut.streamlit.app](https://intrusion-detection-project-ez39lgthrt5ivjb3euazut.streamlit.app)
**🔗 API:** [https://intrusion-detection-project-k5fg.onrender.com](https://intrusion-detection-project-k5fg.onrender.com)

> Note: Both are hosted on free-tier services and may take 30–50 seconds to "wake up" if idle.

## Problem Statement

Network intrusion detection is a natural fit for machine learning, but real-world traffic data is heavily imbalanced — most connections are normal or common attack types, while dangerous attacks like privilege escalation (U2R) are extremely rare. A model can achieve high overall accuracy while almost completely failing to detect these rare, high-severity attacks.

This project uses the **NSL-KDD** dataset, a well-known cybersecurity benchmark, to build a classifier that addresses this imbalance directly, explains its own predictions, and is deployed as a working application.

## Dataset

- **Source:** NSL-KDD (an improved version of the original KDD Cup 99 dataset)
- **Size:** ~126,000 training connections, ~22,500 test connections
- **Features:** 41 per connection (duration, protocol type, byte counts, error rates, login behavior, etc.)
- **Classes:** Normal, DoS, Probe, R2L, U2R

**Class distribution (training data):**

| Class  | Count  | % of Data |
|--------|--------|-----------|
| Normal | 67,343 | 53.46%    |
| DoS    | 45,927 | 36.46%    |
| Probe  | 11,656 | 9.25%     |
| R2L    | 995    | 0.79%     |
| U2R    | 52     | 0.04%     |

## Approach

1. **Baseline model:** Trained an XGBoost classifier with no imbalance handling. Confirmed the problem concretely — R2L recall was just **1%**, despite 76% overall accuracy.
2. **Imbalance handling:** Applied **SMOTE** to the training data to synthetically balance all 5 classes. Also tested SMOTETomek for comparison, which gave only marginal additional improvement.
3. **Explainability:** Integrated **SHAP** (TreeExplainer) so every prediction comes with the specific features that drove it, not just a label.
4. **Serving:** Wrapped the final model in a **FastAPI** backend (`/predict` endpoint returning prediction, confidence, and top contributing factors) and built a **Streamlit** frontend for interactive testing.
5. **Deployment:** Backend deployed on **Render**, frontend on **Streamlit Community Cloud**.

## Results

| Metric              | Before SMOTE | After SMOTE |
|---------------------|:---:|:---:|
| R2L recall          | 1%  | 13% |
| U2R recall          | 16% | 25% |
| Overall accuracy    | 76% | 78% |

R2L and U2R recall remain low in absolute terms even after SMOTE. This was cross-checked against published NSL-KDD research — comparable single-model approaches report similarly low recall on these classes, indicating this is a known, documented difficulty of the dataset rather than a flaw in this approach. 

### Explainability example

### Explainability example

**Global feature importance** — which features matter most for each class overall:

![Global SHAP feature importance](<img width="790" height="940" alt="Unknown" src="https://github.com/user-attachments/assets/c9bf7be1-e14c-4d45-85c8-3694d74cac62" />)

**Individual prediction explanation** — a connection correctly classified as R2L, with the specific features that drove the decision:

![SHAP force plot for R2L prediction](<img width="1570" height="362" alt="Unknown-2" src="https://github.com/user-attachments/assets/46543e84-3bce-4f76-9c2e-6cdd33bcf0b7" />)

The prediction was driven primarily by connection duration (280s), an unusual service-access pattern, and the fact that the user was not logged in — consistent with how R2L attacks (unauthorized remote access attempts) actually behave.

## Tech Stack

**Data & ML:** Python, pandas, NumPy, scikit-learn, XGBoost, imbalanced-learn (SMOTE), SHAP
**Backend:** FastAPI, Pydantic
**Frontend:** Streamlit
**Deployment:** Render (API), Streamlit Community Cloud (frontend)

## Limitations & Honest Notes

- R2L and U2R recall, while significantly improved, are still far from production-ready — this is a documented limitation of the NSL-KDD dataset for these rare classes.
- This project is a demonstration of methodology (imbalance handling, explainability, deployment), not a production-grade security system. A real deployment would need substantially more data on rare attack types, likely an ensemble approach, and human review of flagged connections.
- Free-tier hosting means both services sleep after inactivity, causing a delay on the first request.
