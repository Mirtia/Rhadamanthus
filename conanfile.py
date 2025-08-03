from conan import ConanFile
from conan.tools.cmake import CMake, cmake_layout

class VMIExamplesConan(ConanFile):
    name = "vmi_features_extraction"
    version = "0.0"
    license = "General Lesser Public License v2.1 (LGPL-2.1)"
    author = "Myrsini Gkolemi"
    url = "https://github.com/Mirtia/VMI-Linux-Rootkit-Feature-Collection.git"
    description = "VMI Linux Rootkit Feature Collection"
    settings = "os", "compiler", "build_type", "arch"
    generators = "CMakeDeps", "CMakeToolchain"
    requires = (
        "cjson/1.7.18",
        "glib/2.81.0",
        "log.c/cci.20200620",
        "libyaml/0.2.5"
    )

    def layout(self):
        cmake_layout(self)

    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build()

    def package(self):
        cmake = CMake(self)
        cmake.install()
