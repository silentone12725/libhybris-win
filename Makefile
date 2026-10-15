SHELL := /bin/bash

PYTHON ?= python3
BUILD_DIR ?= .build
ELF_FIXTURE := $(BUILD_DIR)/minimal-x86_64.so

.PHONY: all test unit fixture validate docker-build docker-test clean

all: test

# Stable, offline entry point for the meaningful host-side regression suite.
test: unit fixture

unit:
	./run-tests.sh

fixture: $(ELF_FIXTURE)

$(ELF_FIXTURE): fixtures/generate-minimal-elf.py
	mkdir -p "$(@D)"
	$(PYTHON) "$<" "$@"
	file "$@" | grep -q 'ELF 64-bit.*x86-64'

# Alias used by CI and by the README's validation instructions.
validate: test

docker-build:
	docker build --tag libhybris-win:test .

docker-test:
	docker run --rm --network none libhybris-win:test

clean:
	rm -rf "$(BUILD_DIR)"
