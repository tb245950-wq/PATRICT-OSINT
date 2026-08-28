from setuptools import setup, find_packages

setup(
    name="patrict-osint",
    version="2.5.0",
    description="Automated Multi-Domain OSINT & Digital Forensics Framework",
    author="Muhammad Mughni",
    author_email="rootacces@proton.me",
    url="https://github.com/tb245950-wq/PATRICT-OSINT",
    project_urls={
        "Homepage": "https://github.com/tb245950-wq/PATRICT-OSINT",
        "Source": "https://github.com/tb245950-wq/PATRICT-OSINT.git",
        "Documentation": "https://github.com/tb245950-wq/PATRICT-OSINT#readme",
        "Issue Tracker": "https://github.com/tb245950-wq/PATRICT-OSINT/issues",
        "Community": "https://discord.gg/snGDCZT2E",
        "Creator": "https://github.com/tb245950-wq"
    },
    keywords=[
        "osint",
        "patrict-osint",
        "patrick-osint",
        "muhammad-mughni",
        "cybersecurity",
        "reconnaissance",
        "digital-forensics",
        "whatweb",
        "threat-intelligence"
    ],
    py_modules=["main"],
    packages=find_packages(),
    install_requires=[
        "phonenumbers>=8.13.0",
        "geopy>=2.4.0",
        "folium>=0.15.0",
        "beautifulsoup4>=4.12.0",
        "dnspython>=2.4.0",
        "aiohttp>=3.9.0",
        "pyyaml>=6.0.0",
        "jinja2>=3.1.0",
        "networkx>=3.2.0",
        "pyvis>=0.3.2",
        "requests>=2.31.0",
        "python-dotenv>=1.0.0",
        "pillow>=10.0.0"
    ],
    entry_points={
        "console_scripts": [
            "osint=main:main",
            "patrict=main:main",
            "patrict-osint=main:main"
        ],
    },
    include_package_data=True,
    package_data={
        "": ["*.json", "*.html", "*.yaml", "*.yml"],
        "data": ["*.json"],
        "reports": ["templates/*.html"],
    },
    python_requires=">=3.8",
)
