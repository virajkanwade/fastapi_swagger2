import os

import nox

# Test matrix: Python versions and FastAPI versions
PYTHON_VERSIONS = ["3.10", "3.11", "3.12", "3.13", "3.14"]
FASTAPI_VERSIONS = ["==0.140.7", "latest"]

nox.options.default_venv_backend = "uv"


@nox.session(python=PYTHON_VERSIONS)
@nox.parametrize("fastapi_version", FASTAPI_VERSIONS)
def test(session, fastapi_version):
    """Test against different Python and FastAPI versions."""

    session.log("")
    session.log(f"🐍 Testing Python {session.python} with FastAPI {fastapi_version}")
    session.log("=" * 60)

    # Check if submodule exists
    if not os.path.exists("tests/integration/petstore/.git"):
        session.error("Petstore submodule not found. Run: git submodule update --init --recursive")

    # Install current library
    session.install("-e", ".")

    # Install specific FastAPI version
    if fastapi_version == "latest":
        session.install("--upgrade", "fastapi")
        session.run("python", "-c", "import fastapi; print(f'FastAPI {fastapi.__version__}')")
    else:
        session.install(f"fastapi{fastapi_version}")

    # Change to test project and install its dependencies
    with session.chdir("tests/integration/petstore/src"):
        # Generate swagger2.json
        session.run("python", "-c", """
import sys
sys.path.insert(0, '.')
from openapi_server.main import app
import json

# Get swagger2 spec
spec = app.swagger2()

# Write to file
with open('generated_swagger2.json', 'w') as f:
    json.dump(spec, f, indent=2, sort_keys=True)

print(f'Generated swagger2.json for Python {sys.version_info.major}.{sys.version_info.minor}')
""")

        # Compare with reference
        reference_file = "../tests/reference/swagger2.json"
        if os.path.exists(reference_file):
            import filecmp
            if filecmp.cmp("generated_swagger2.json", reference_file, shallow=False):
                session.log("✅ Integration test PASSED")
                session.log("")
            else:
                session.log("")
                session.log("❌ DIFFERENCES FOUND:")
                session.log("-" * 40)
                # Show diff
                import difflib
                with open("generated_swagger2.json") as f1, open(reference_file) as f2:
                    diff = difflib.unified_diff(
                        f2.readlines(), f1.readlines(),
                        fromfile="reference", tofile="generated",
                        lineterm=""
                    )
                    session.log("Differences found:")
                    for line in diff:
                        session.log(line)
                session.log("-" * 40)
                session.log("")
                session.error("❌ Integration test FAILED - JSON differs from reference")
        else:
            session.error(
                "📝 No reference file found. Run 'python scripts/generate_reference.py' in petstore project first."
            )
