.PHONY: vmi clean build test

clean:
	rm -rf build

build:
	conan install . --build=missing
	conan build . 

test: build
	cd build && sudo -E ctest --output-on-failure --verbose