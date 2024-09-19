import os
import json
import csv
import argparse
import subprocess
import sys

def find_repositories(directory):
    #Locates repositories in the given directory containing 'requirements.txt' and/or 'package.json'
    #Returns a list of paths containing requirements or packages
    repositories = []
    for subdir, dirs, files in os.walk(directory):
        if 'requirements.txt' in files or 'package.json' in files:
            repositories.append(subdir)
    print(f'Found {len(repositories)} repositorie(s) in \'{directory}\'')
    return repositories


def parse_requirements(file_path):
    #Parses through the requirements.txt file and stores the found dependencies in list 
    #in the format of (name, version, pip, file_path, direct)
    dependencies = []
    try:
        with open(file_path, 'r') as f:
            for line in f:
                if '==' in line:
                    name, version = line.strip().split('==')
                    dependencies.append((name, version, 'pip', file_path, 'direct'))
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
    return dependencies

def parse_package_json(file_path):
    #Parses through the package.json file and stores the found dependencies in list 
    #in the format of (name, version, npm, file_path, direct)
    dependencies = []
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
            for name, version in data.get('dependencies', {}).items():
                dependencies.append((name, version, 'npm', file_path, 'direct'))
    except json.JSONDecodeError:
        print(f"Invalid JSON in {file_path}")
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
    return dependencies

def parse_package_lock_json(file_path):
    #Parses through the package-lock.json file and stores the found dependencies in list 
    #in the format of (name, version, npm, file_path, indirect)
    dependencies = []
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
            for name, details in data.get('dependencies', {}).items():
                version = details.get('version')
                if version:
                    dependencies.append((name, version, 'npm', file_path, 'indirect'))
    except json.JSONDecodeError:
        print(f"Invalid JSON in {file_path}")
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
    return dependencies

def get_git_commit(repo_path):
    #Retireves the last known git commit hash for the repository
    try:
        commit_hash = subprocess.check_output(
            ['git', '-C', repo_path, 'log', '--format=%H', '-n', '1'],
            stderr=subprocess.STDOUT
        ).decode('utf-8').strip()
        return commit_hash
    except subprocess.CalledProcessError as e:
        print(f"Could not retrieve git commit for {repo_path}: {e}")
        return None

def generate_sbom(directory, output_csv, output_json):
    #Generates the SBOM based on the parse functions above and generates both a 
    #CSV file (sbom.csv) in the format of ('name', 'version', 'type', 'file_path', 'dependency_type', 'git_commit')
    #and a JSON file (sbom.json) in the format of: 
    """'name': entry[0],
       'version': entry[1],
        'type': entry[2],
        'file_path': entry[3],
        'dependency_type': entry[4],
        'git_commit': entry[5]
    """
    repositories = find_repositories(directory)
    if not repositories:
        print("No repositories with 'requirements.txt' or 'package.json' found.")
        sys.exit(1)  # Exit with a failure code for No repositories found
    
    sbom_entries = []

    for repo in repositories:
        git_commit = get_git_commit(repo)

        if not git_commit:
            print(f"Warning: No Git commit found for {repo}. Proceeding without commit information.")

        if 'requirements.txt' in os.listdir(repo):
            try:
                sbom_entries.extend([(*dep, git_commit) for dep in parse_requirements(os.path.join(repo, 'requirements.txt'))])
            except Exception as e:
                print(f"Error processing requirements.txt in {repo}: {e}")
                sys.exit(2)  # Exit with a failure code for Error in reading requirements.txt file

        if 'package.json' in os.listdir(repo):
            try:
                sbom_entries.extend([(*dep, git_commit) for dep in parse_package_json(os.path.join(repo, 'package.json'))])
            except Exception as e:
                print(f"Error processing package.json in {repo}: {e}")
                sys.exit(3) # Exit with a failure code for Error in reading package.json file

        if 'package-lock.json' in os.listdir(repo):
            try:
                sbom_entries.extend([(*dep, git_commit) for dep in parse_package_lock_json(os.path.join(repo, 'package-lock.json'))])
            except Exception as e:
                print(f"Error processing package-lock.json in {repo}: {e}")
                sys.exit(4) # Exit with a failure code for Error in reading package-lock.json file

    if sbom_entries:
        with open(output_csv, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['name', 'version', 'type', 'file_path', 'dependency_type', 'git_commit'])
            for entry in sbom_entries:
                writer.writerow(entry)
        print(f'Saved SBOM in CSV format to {output_csv}')

        with open(output_json, 'w') as jsonfile:
            json.dump([{
                'name': entry[0],
                'version': entry[1],
                'type': entry[2],
                'file_path': entry[3],
                'dependency_type': entry[4],
                'git_commit': entry[5]
            } for entry in sbom_entries], jsonfile, indent=4)
        print(f'Saved SBOM in JSON format to {output_json}')
    else:
        print(f"No dependencies found in the repositories under {directory}.")
        sys.exit(0)  # No errors but no dependencies found

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Generate an SBOM from Python and JavaScript dependencies")
    parser.add_argument('directory', help="Directory path containing repositories")
    
    args = parser.parse_args()
    directory = args.directory
    output_csv = os.path.join(directory, 'sbom.csv')
    output_json = os.path.join(directory, 'sbom.json')
    
    generate_sbom(directory, output_csv, output_json)
