from conan import ConanFile
from conan.tools.cmake import CMake, cmake_layout

class VMIExamplesConan(ConanFile):
    name = "vmi_examples"
    version = "0.1"
    license = "MIT"  # Change as appropriate
    author = "Your Name"
    url = "https://your.repo.url"
    description = "VMI Linux Rootkit Feature Collection"
    settings = "os", "compiler", "build_type", "arch"
    generators = "CMakeDeps", "CMakeToolchain"
    requires = (
        "cjson/1.7.18",
        "glib/2.81.0"
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
