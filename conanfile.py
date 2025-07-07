from conans import ConanFile, CMake, tools
from conans.errors import ConanInvalidConfiguration
import os
import re


def get_version():
    if re.match(r"^release-.*", os.getenv("CI_COMMIT_REF_NAME", "")):
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
    else:
        return "dev"


def branch_to_channel(branch):
    if re.match(r"^release-.*", branch):
        return "stable"
    else:
        return branch.replace("/", "+")


class Properties:
    name = "gtirb-pprinter"
    version = get_version()
    rel_url = "rewriting/gtirb-pprinter"
    exports_sources = "*", "!.conan/*"

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
        if "CI_COMMIT_REF_NAME" in os.environ:
            branch = os.environ["CI_COMMIT_REF_NAME"]
            channel = branch_to_channel(branch)
        return channel

    # Add to this list branch names to have conan packages for
    # branches archived in gitlab.
    @property
    def archived_channels(self):
        # Add to this list branch names to have conan packages for
        # branches archived in gitlab.
        archived_branches = ["master"]
        # Also, archive the 'stable' channel, where all stable versions
        # will be uploaded
        archived_channels = ["stable"]
        return archived_channels + list(
            map(branch_to_channel, archived_branches)
        )

    @property
    def conan_ref(self):
        return "%s/%s" % (self.rel_url.replace("/", "+"), self.conan_channel)

    @property
    def conan_recipe(self):
        return "%s/%s@%s" % (self.name, self.version, self.conan_ref)


class GtirbPprinterConan(Properties, ConanFile):
    boost_version = "1.69.0"
    gtirb_version = "2.3.0"
    capstone_version = "5.0.1-gt"
    requires = (
        "boost/%s" % (boost_version),
        "gtirb/%s@rewriting+gtirb/stable" % (gtirb_version),
        "capstone/%s@rewriting+extra-packages/next" % (capstone_version),
    )
    author = "GrammaTech Inc."
    generators = "cmake"
    settings = ("os", "compiler", "build_type", "arch")
    options = {"run_tests": [True, False, None]}

    def imports(self):
        self.copy("*.dll", "bin", "bin")

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

    def build(self):
        if self.settings.os == "Windows":
            with tools.vcvars(
                self.settings, force=True, filter_known_paths=False
            ):
                self.build_cmake()
        else:
            self.build_cmake()

    def add_dep_lib_path(self, *deps):
        lib_dirs = sum([self.deps_cpp_info[dep].lib_paths for dep in deps], [])
        new_ld_lib_path = [os.environ.get("LD_LIBRARY_PATH", "")] + lib_dirs
        os.environ["LD_LIBRARY_PATH"] = os.pathsep.join(new_ld_lib_path)

    def build_cmake(self):
        defs = {"CMAKE_VERBOSE_MAKEFILE:BOOL": "ON", "ENABLE_CONAN:BOOL": "ON"}
        if self.settings.os == "Windows":
            cmake = CMake(self, generator="Ninja")
            defs.update({k: os.environ.get(k) for k in ["CMAKE_PREFIX_PATH"]})
            defs["Boost_USE_STATIC_LIBS"] = "ON"
        else:
            cmake = CMake(self, generator=None)
            defs.update({"GTIRB_PPRINTER_STRIP_DEBUG_SYMBOLS:BOOL": "ON"})

        revision = os.environ.get("CI_COMMIT_SHORT_SHA")
        if revision:
            defs["GTIRB_PPRINTER_BUILD_REVISION"] = revision

        if self.settings.build_type == "Release":
            cmake.build_type = "RelWithDebInfo"
        self.add_dep_lib_path("capstone")
        cmake.configure(source_folder=".", defs=defs)
        cmake.build()

        run_tests = (
            self.options.run_tests or self.options.run_tests == None
        )  # noqa: E711

        if run_tests:
            # The tests need the built gtirb-pprinter on the path
            bin_dir = os.path.join(os.getcwd(), "bin")
            os.environ["PATH"] = os.pathsep.join([os.environ["PATH"], bin_dir])
            cmake.test(output_on_failure=True)

        cmake.install()
        # The patch_config_paths() function will change absolute paths in the
        # exported cmake config files to use the appropriate conan variables
        # instead.
        # It is an experimental feature of conan, however, so if you're having
        # trouble with paths in the cmake of the conan package, it could that
        # this function is no longer doing what we want.
        cmake.patch_config_paths()

    def build_requirements(self):
        if self.settings.os == "Windows":
            self.build_requires("ninja/1.10.2")

    def package(self):
        self.copy("*.h", dst="include", src=self.name)
        self.copy("*%s.lib" % (self.name), dst="lib", keep_path=False)
        for name in ("gtirb_pprinter", "gtirb_layout"):
            self.copy(f"{name}.dll", dst="bin", keep_path=False)
            self.copy(f"lib{name}*.so", dst="lib", keep_path=False)
            self.copy(f"lib{name}*.so.*", dst="lib", keep_path=False)
        self.copy("*.dylib", dst="lib", keep_path=False)
        self.copy("*.a", dst="lib", keep_path=False)

    def package_info(self):
        self.cpp_info.libs = [self.name]
