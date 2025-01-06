import yaml
import os

def load_yaml(file_path):
    """Load a YAML file and return its content."""
    try:
        with open(file_path, 'r') as f:
            return list(yaml.safe_load_all(f))
    except yaml.YAMLError as e:
        print(f"Error parsing YAML file {file_path}: {e}")
        return []

def detect_code_smells(manifests):
    """Detect Kubernetes code smells in the given YAML manifests."""
    smells = []

    for manifest in manifests:
        if not isinstance(manifest, dict):
            continue

        kind = manifest.get('kind', 'Unknown')
        metadata = manifest.get('metadata', {})
        name = metadata.get('name', 'Unknown')
        namespace = metadata.get('namespace', 'default')
        spec = manifest.get('spec', {})

        # Detect hardcoded values (example: using 'latest' tag)
        if 'containers' in spec:
            for container in spec['containers']:
                image = container.get('image', '')
                if ':latest' in image or image == 'latest':
                    smells.append(f"[Hardcoded Value] {kind}/{name} in namespace {namespace} uses 'latest' tag for image {image}.")

        # Detect missing resource requests and limits
        if 'containers' in spec:
            for container in spec['containers']:
                resources = container.get('resources', {})
                if 'requests' not in resources or 'limits' not in resources:
                    smells.append(f"[Resource Smell] {kind}/{name} in namespace {namespace} is missing resource requests or limits.")

        # Detect overprivileged pods
        if kind == 'Pod' and spec.get('securityContext', {}).get('privileged', False):
            smells.append(f"[Overprivileged Pod] {kind}/{name} in namespace {namespace} is running as privileged.")

        # Detect missing probes
        if 'containers' in spec:
            for container in spec['containers']:
                if 'livenessProbe' not in container:
                    smells.append(f"[Health Check] {kind}/{name} in namespace {namespace} is missing a livenessProbe.")
                if 'readinessProbe' not in container:
                    smells.append(f"[Health Check] {kind}/{name} in namespace {namespace} is missing a readinessProbe.")

        # Detect large ConfigMaps
        if kind == 'ConfigMap':
            data = manifest.get('data', {})
            if len(data) > 100:  # Arbitrary threshold
                smells.append(f"[Large ConfigMap] {kind}/{name} in namespace {namespace} has a large number of entries ({len(data)}).")

        # Detect secrets in plain text
        if kind == 'Secret':
            data = manifest.get('data', {})
            if any(len(value) > 100 for value in data.values()):  # Arbitrary threshold
                smells.append(f"[Secret Smell] {kind}/{name} in namespace {namespace} has potentially large plain-text entries.")

        # Detect using default namespace
        if namespace == 'default':
            smells.append(f"[Namespace Smell] {kind}/{name} is in the default namespace.")

    return smells

def scan_directory(directory):
    """Scan a directory for Kubernetes YAML files and check for code smells."""
    all_smells = []
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(('.yaml', '.yml')):
                file_path = os.path.join(root, file)
                manifests = load_yaml(file_path)
                smells = detect_code_smells(manifests)
                if smells:
                    all_smells.append((file_path, smells))
    return all_smells

if __name__ == "__main__":
    directory = input("Enter the directory containing Kubernetes YAML files: ")
    results = scan_directory(directory)

    if results:
        print("\nDetected Kubernetes Code Smells:")
        for file_path, smells in results:
            print(f"\nFile: {file_path}")
            for smell in smells:
                print(f"  - {smell}")
    else:
        print("No code smells detected.")
