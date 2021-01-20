from conans import ConanFile, CMake, tools
from conans.errors import ConanInvalidConfiguration
import os
import re


def get_version():
    try:
        with open("version.txt") as f:
            s = f.read()
            match = re.search(
                r"VERSION_MAJOR(\s+)(\S+)(\s+)"
                r"VERSION_MINOR(\s+)(\S+)(\s+)"
                r"VERSION_PATCH(\s+)(\S+)(\s+)",
                s,
            )
            if match:
                major = match.group(2)
                minor = match.group(5)
                patch = match.group(8)
                return major + "." + minor + "." + patch
            else:
                return "<ERROR: no version found>"
    except Exception:
        return None


def branch_to_channel(branch):
    if branch == "master":
        return "stable"
    else:
        return branch.replace("/", "+")


class Properties:
    name = "gtirb-pprinter"
    version = get_version()
    rel_url = "rewriting/gtirb-pprinter"

    @property
    def description(self):
        return (
            "A pretty printer from the GTIRB intermediate representation "
            "for binary analysis and reverse engineering to gas-syntax "
            "assembly code."
        )

    @property
    def url(self):
        return "https://git.grammatech.com/%s" % self.rel_url

    @property
    def conan_channel(self):
        channel = "local"
        if "CI_COMMIT_BRANCH" in os.environ:
            branch = os.environ["CI_COMMIT_BRANCH"]
            channel = branch_to_channel(branch)
        return channel

    # Add to this list branch names to have conan packages for
    # branches archived in gitlab.
    @property
    def archived_channels(self):
        archived_branches = ["master"]
        return list(map(branch_to_channel, archived_branches))

    @property
    def conan_ref(self):
        return "%s/%s" % (self.rel_url.replace("/", "+"), self.conan_channel)

    @property
    def conan_recipe(self):
        return "%s/%s@%s" % (self.name, self.version, self.conan_ref)


class GtirbPprinterConan(Properties, ConanFile):
    boost_version = "1.69.0"
    gtirb_version = "1.10.0"
    capstone_version = "4.0.1"
    requires = (
        "boost/%s@conan/stable" % (boost_version),
        "gtirb/%s@rewriting+gtirb/stable" % (gtirb_version),
        "capstone/%s@rewriting+pkg-capstone/next" % (capstone_version),
    )
    author = "GrammaTech Inc."
    generators = "cmake"
    settings = ("os", "compiler", "build_type", "arch")

    def configure(self):
        if (
            self.settings.compiler == "gcc"
            and self.settings.compiler.libcxx != "libstdc++11"
        ):
            raise ConanInvalidConfiguration(
                (
                    "gtirb-pprinter requires libstdc++11 ABI, update your "
                    "conan profile"
                )
            )

    def source(self):
        project_dir = os.environ["CI_PROJECT_DIR"]
        self.run("git clone %s %s" % (project_dir, self.name))

    def build(self):
        if self.settings.os == "Windows":
            with tools.vcvars(
                self.settings, force=True, filter_known_paths=False
            ):
                self.build_cmake()
        else:
            self.build_cmake()

    def build_cmake(self):
        defs = {"CMAKE_VERBOSE_MAKEFILE:BOOL": "ON", "ENABLE_CONAN:BOOL": "ON"}
        if self.settings.os == "Windows":
            cmake = CMake(self, generator="Ninja")
            defs.update(
                {
                    k: os.environ.get(k)
                    for k in ["BOOST_ROOT", "CMAKE_PREFIX_PATH", "PYTHON"]
                }
            )
            defs["Boost_USE_STATIC_LIBS"] = "ON"
        else:
            cmake = CMake(self, generator=None)
            defs.update(
                {
                    "CMAKE_CXX_COMPILER": "g++-7",
                    "GTIRB_PPRINTER_STRIP_DEBUG_SYMBOLS:BOOL": "ON",
                }
            )

        cmake.configure(source_folder=self.name, defs=defs)
        cmake.build()
        # The tests need the built gtirb-pprinter on the path
        bin_dir = os.path.join(os.getcwd(), "bin")
        os.environ["PATH"] = os.environ.get("PATH") + ":%s" % bin_dir
        cmake.test()
        cmake.install()

    def build_requirements(self):
        if self.settings.os == "Windows":
            self.build_requires("ninja_installer/1.9.0@bincrafters/stable")

    def package(self):
        self.copy("*.h", dst="include", src=self.name)
        self.copy("*%s.lib" % (self.name), dst="lib", keep_path=False)
        self.copy("*.dll", dst="bin", keep_path=False)
        self.copy("*.so", dst="lib", keep_path=False)
        self.copy("*.dylib", dst="lib", keep_path=False)
        self.copy("*.a", dst="lib", keep_path=False)

    def package_info(self):
        self.env_info.path.append(os.path.join(os.getcwd(), "bin"))
        self.cpp_info.libs = [self.name]
