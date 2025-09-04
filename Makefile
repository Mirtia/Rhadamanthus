.PHONY: vmi clean build test single_test format check-format
CLANG_FORMAT ?= clang-format
FORMAT_STYLE ?= file
DOXYGEN ?= doxygen
DOXYGEN_CONFIG ?= config/Doxyfile

clean:
	rm -rf build docs/html docs/latex

build:
	conan install . --build=missing
	conan build .

test: build
	cd build && sudo -E ctest --output-on-failure --verbose

single_test: build
	# e.g. DispatcherTest
	cd build && sudo -E ctest --output-on-failure --verbose -R '$(TEST)'

format:
	echo "Formatting (*.c,*.h)..."
	find . -type f \( -name '*.c' -o -name '*.h' \) \
		-not -path './build/*' -not -path '*/.git/*' -print0 | \
		xargs -0 -n 50 $(CLANG_FORMAT) -i -style=$(FORMAT_STYLE)

check-format:
	echo "Checking format..."
	find . -type f \( -name '*.c' -o -name '*.h' \) \
		-not -path './build/*' -not -path '*/.git/*' -print0 | \
		# Issue with reordering of imports and mocka tests.
		-not -path './tests/*' \
		xargs -0 -n 50 $(CLANG_FORMAT) -n --Werror -style=$(FORMAT_STYLE)

doxygen:
	@if [ ! -f $(DOXYGEN_CONFIG) ]; then \
		echo "Doxygen config ($(DOXYGEN_CONFIG)) not found. Generate one with 'doxygen -g'"; \
		exit 1; \
	fi
	$(DOXYGEN) $(DOXYGEN_CONFIG)
	echo "Documentation generated in docs/html (and docs/latex if enabled)."