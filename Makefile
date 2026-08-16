PYTHON   := python3
PYTEST   := $(shell command -v pytest 2>/dev/null || echo $(PYTHON) -m pytest)
VENV     := $(HOME)/rai
BIN      := $(VENV)/bin

.PHONY: all install install-tools test clean

all: test

install:
	$(BIN)/pip install -e .

install-tools:
	@if ! command -v osslsigncode &>/dev/null; then \
		echo "[*] building osslsigncode from source..."; \
		cd /tmp && git clone --depth=1 https://github.com/mtrojnar/osslsigncode.git && \
		cd osslsigncode && cmake -B build . && cmake --build build && \
		install -Dm755 build/osslsigncode $(HOME)/.local/bin/osslsigncode && \
		echo "[+] osslsigncode installed to ~/.local/bin/"; \
	else \
		echo "[+] osslsigncode already available"; \
	fi

test:
	PYTHONPATH=. $(BIN)/pytest tests/ -q

test-v:
	PYTHONPATH=. $(BIN)/pytest tests/ -v

# sign all PE outputs under a given directory
# usage: make sign-dir DIR=/path/to/outputs
sign-dir:
	@test -n "$(DIR)" || (echo "usage: make sign-dir DIR=<path>" && exit 1)
	$(PYTHON) -m keymaker batch $(DIR) -r

clean:
	rm -rf __pycache__ keymaker/__pycache__ tests/__pycache__ .pytest_cache *.egg-info
