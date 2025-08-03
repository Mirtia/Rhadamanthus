CODE_DIR = src

.PHONY: vmi clean build

vmi:
	$(MAKE) -C $(CODE_DIR)
	cp $(CODE_DIR)/vmi ./

clean:
# 	$(MAKE) -C $(CODE_DIR) clean
	rm -rf build

build:
	conan install . --build=missing
	conan build . 

