# 🛡️ ShieldAI Intel v3.0 — Hybrid URL Phishing Detection Platform

ShieldAI Intel is an enterprise-grade, multi-page web application designed to analyze and detect phishing URLs in real time. Built with Python, Flask, Scikit-Learn, and dynamic JavaScript visualizers, the platform evaluates threats across a 3-layer security verification framework.

---

## Features

* ** Multi-Layer Threat Inspector:** Combines authority whitelisting (`tldextract`), lexical feature analysis, domain age inspection (`python-whois`), and brand-spoofing heuristics.
* **  Random Forest Machine Learning:** Evaluates URL lexical structure using a trained Scikit-Learn classification model to output precise probability risk scores.
* ** Dynamic Threat Analytics Dashboard:** Interactive telemetry charts powered by `Chart.js` with configurable time-range filters (24h, 7d, 30d, All Time) and a live streaming threat feed.
* ** Bulk Batch Inspector:** Asynchronously inspects up to 10 URLs simultaneously and exports structured JSON compliance reports.
* ** Interactive API Playground:** Built-in REST API documentation with live endpoint testing, JSON response streaming, and one-click code snippets (Python, JS, cURL).

---

##  Tech Stack

* **Backend:** Python 3, Flask, Scikit-Learn, Joblib, TLDExtract, Python-Whois
* **Frontend:** HTML5, CSS3 (Glassmorphism UI), JavaScript (ES6+), Chart.js
* **Architecture:** RESTful API Architecture, Async Fetch Pipelines

---

##  Quickstart Guide

### 1. Clone the Repository
```bash
git clone [https://github.com/karan23cs205/Phishing-URL-Detector-Website.git](https://github.com/karan23cs205/Phishing-URL-Detector-Website.git)
cd Phishing-URL-Detector-Website