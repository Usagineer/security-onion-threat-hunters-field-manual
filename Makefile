# Security Onion Threat Hunter's Field Manual — build system
#
# Generates Word (.docx) and PDF releases from the Markdown sources.
# Requires: pandoc (https://pandoc.org). PDF requires a LaTeX engine
# (e.g. tectonic / xelatex) or weasyprint.

PANDOC      ?= pandoc
BUILD       := build
SRC_DIR     := manual
# Order matters: front matter first, then phases in numeric order.
SOURCES     := $(SRC_DIR)/00-front-matter.md $(sort $(wildcard $(SRC_DIR)/phase-*.md))

TITLE       := Security Onion Threat Hunter's Field Manual
PDF_ENGINE  ?= xelatex

COMMON_OPTS := --from=gfm+emoji \
               --toc --toc-depth=2 \
               --metadata title="$(TITLE)" \
               --resource-path=$(SRC_DIR)

.PHONY: all docx pdf clean

all: docx pdf

$(BUILD):
	mkdir -p $(BUILD)

## docx: build the combined manual as Word
docx: | $(BUILD)
	$(PANDOC) $(COMMON_OPTS) $(SOURCES) -o $(BUILD)/security-onion-field-manual.docx

## pdf: build the combined manual as PDF
pdf: | $(BUILD)
	$(PANDOC) $(COMMON_OPTS) --pdf-engine=$(PDF_ENGINE) $(SOURCES) -o $(BUILD)/security-onion-field-manual.pdf

## clean: remove generated output
clean:
	rm -rf $(BUILD)
