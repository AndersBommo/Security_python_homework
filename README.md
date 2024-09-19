
# SBOM Generator for Python and JavaScript Projects

This tool generates a Software Bill of Materials (SBOM) for Python and JavaScript repositories. It scans directories containing repositories, identifies dependencies from requirements.txt (for Python) and package.json/package-lock.json (for JavaScript), and generates SBOMs in both CSV and JSON formats.

### GIT CLONE COMMAND:  
git clone https://github.com/AndersBommo/Security_python_homework.git

### The SBOM generated includes:
    - Dependency name
    - Version
    - Type (pip or npm)
    - File path where the dependency was found
    - Whether the dependency is direct or indirect (for JavaScript)
    - The latest Git commit hash of the repository

### HOW TO: 

Run script in python3 or later with command below with path to your directory as shown below:

python3 sbom.py /path/to/your/directory

### Exit Codes:
1: No repositories found.
2: Error reading requirements.txt.
3: Error reading package.json.
4: Error reading package-lock.json.


### Future improvements
#### Dependency Vulnerability Checks:
Integrate a vulnerability scanning tool (such as using CVE databases) to check if any listed dependencies have known vulnerabilities.

#### Improved formatting
Expand on the formatting to have by more details in the SBOM files with information on author, repository URL. Filters could be added so that the user can filter certain dependencies

#### Support for more Dependency managers 
Expand the script to accept other package managers for languages such as C/C++, Rust
