.PHONY: vmi clean build test single_test

clean:
	rm -rf build

build:
	conan install . --build=missing
	conan build . 

test: build
	cd build && sudo -E ctest --output-on-failure --verbose

single_test: build
	# e.g. DispatcherTest
	cd build && sudo -E ctest --output-on-failure --verbose -R '$(TEST)'