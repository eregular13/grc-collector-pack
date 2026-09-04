PYTHON ?= $(shell command -v python3 >/dev/null 2>&1 && echo python3 || echo python)
export PYTHONPATH := $(CURDIR)
export OUT_DIR := $(CURDIR)/out
export DRY_RUN := 1
export GRC_LIVE_SCAN := 0
export CISO_PUSH := 0
export RISKREADY_PUSH := 0

.PHONY: lab test collectors loader compose safety product

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
	$(PYTHON) tests/lab_outputs.py

compose:
	docker compose up --build --exit-code-from grc-loader

safety:
	$(PYTHON) -m pytest tests/test_safety.py -q

product:
	$(PYTHON) -m product
