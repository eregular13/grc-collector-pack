# GRC collector pack — optional GNU Make targets (Unix/WSL).
#
# Windows real lab entry (required):
#   powershell -ExecutionPolicy Bypass -File .\run_lab.ps1
# run_lab.ps1 is the real lab gate: pytest, nine collectors, loader
# (double-run / idempotent counts), tests\lab_outputs.py, and a
# non-fatal Docker daemon probe.
# `make lab` approximates the Python portions only and does not replace
# run_lab.ps1 on Windows.

PYTHON ?= python
export PYTHONPATH := .
export DRY_RUN := 1
export CISO_PUSH := 0
export RISKREADY_PUSH := 0
export GRC_LIVE_SCAN := 0

.PHONY: help lab test collectors loader compose

help:
	@echo Windows real lab entry: powershell -ExecutionPolicy Bypass -File .\run_lab.ps1
	@echo GNU make lab is optional and does not replace run_lab.ps1 on Windows.

test:
	$(PYTHON) -m pytest tests -q

collectors:
	$(PYTHON) collectors/cloud_prowler.py
	$(PYTHON) collectors/inventory_nmap.py
	$(PYTHON) collectors/vuln_scan.py
	$(PYTHON) collectors/host_wazuh.py
	$(PYTHON) collectors/identity_ad.py
	$(PYTHON) collectors/easm.py
	$(PYTHON) collectors/k8s_kubescape.py
	$(PYTHON) collectors/code_secrets.py
	$(PYTHON) collectors/saas_idp.py

loader:
	$(PYTHON) collectors/grc_loader.py

lab: test collectors loader
	$(PYTHON) tests/lab_outputs.py --stamp
	@echo NOTE: On Windows the real lab entry is run_lab.ps1

compose:
	docker compose up --build --abort-on-container-exit
