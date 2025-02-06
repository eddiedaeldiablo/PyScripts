import subprocess
import sys

# List of required Python libraries
REQUIRED_LIBS = [
    "requests",
    "beautifulsoup4",
    "python-whois",
    "pdfkit",
    "difflib",
    "html5lib",
    "scikit-learn"
]

def install_dependencies():
    """Installs required Python packages using pip."""
    print("\n🚀 Installing Required Dependencies...\n")
    
    for lib in REQUIRED_LIBS:
        try:
            subprocess.run([sys.executable, "-m", "pip", "install", lib], check=True)
            print(f"✅ {lib} installed successfully!")
        except subprocess.CalledProcessError:
            print(f"❌ Failed to install {lib}. Try manually using: python3 -m pip install {lib}")

def verify_installation():
    """Verifies if all dependencies are installed."""
    print("\n🔍 Verifying Installation...\n")
    
    missing_libs = []
    for lib in REQUIRED_LIBS:
        try:
            __import__(lib.replace("-", "_"))
        except ImportError:
            missing_libs.append(lib)

    if missing_libs:
        print(f"⚠️ Missing libraries: {', '.join(missing_libs)}")
        print("⚠️ Please run the script again or install manually using:")
        print(f"   python3 -m pip install {' '.join(missing_libs)}")
        return False
    else:
        print("✅ All required libraries are installed.")
        return True

if __name__ == "__main__":
    install_dependencies()
    verify_installation()
