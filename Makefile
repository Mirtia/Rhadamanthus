CODE_DIR = src

.PHONY: vmi clean build

vmi:
	$(MAKE) -C $(CODE_DIR)
	cp $(CODE_DIR)/vmi ./

clean:
	$(MAKE) -C $(CODE_DIR) clean
	rm -rf vmi

build:
	conan install . --output-folder=build --build=missing
	conan build .
