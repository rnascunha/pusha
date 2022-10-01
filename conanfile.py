from conans import ConanFile, CMake, tools

class PushaConan(ConanFile):
    name = "pusha"
    version = "0.1"
    license = "MIT"
    author = "Rafael Cunha <rnascunha@gmail.com>"
    url = "https://github.com/rnascunha/pusha"
    description = "C/C++ implementation of Web Push"
    topics = ("web", "web push", "notification")
    settings = "os", "compiler", "build_type", "arch"
    options = {"shared": [True, False], "fPIC": [True, False], "tools": [True, False]}
    default_options = {"shared": False, "fPIC": True, "tools": False}
    generators = "cmake_find_package"
    exports = "LICENSE", "README.md", "URL.txt"
    exports_sources = "third/*", "*.c", "*.cpp", "*.h", "*.hpp", "*.cmake", "CMakeLists.txt"
    requires = "openssl/1.1.1q"

    def config_options(self):
        if self.settings.os == "Windows":
            del self.options.fPIC

    def build(self):
        cmake = CMake(self)
        cmake.definitions["WITH_TOOLS"] = self.options.tools
        cmake.configure()
        cmake.build()

    def package(self):
        #ECEC depends
        self.copy("*.h", dst="third", src="third")
        self.copy("*.c", dst="third", src="third")
        #C API
        self.copy("*.h", dst="include", src="include")
        self.copy("*.c", dst="src", src="src")
        #CPP API
        self.copy("*.cpp", dst="src", src="src_cpp")
        self.copy("*.hpp", dst="include", src="include_cpp")
        #libs
        self.copy("*.dll", dst="bin", keep_path=False)
        self.copy("*.so", dst="lib", keep_path=False)
        self.copy("*.dylib", dst="lib", keep_path=False)
        self.copy("*.a", dst="lib", keep_path=False)
        #tools
        # self.copy("*", dst="bin", src="tools", keep_path=False)

    def package_info(self):
        self.cpp_info.includedirs = ["include", "third/ecec/include"]
        self.cpp_info.libs = ["pusha"]

