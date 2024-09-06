import subprocess
import yaml

def get_kubeconfig():
    result = subprocess.run(['kubectl', 'config', 'view', '--raw'], stdout=subprocess.PIPE)
    output = result.stdout.decode('utf-8')
    return yaml.safe_load(output)


def get_client_credentials():
    kubeconfig = get_kubeconfig()
    contexts = kubeconfig['contexts']
    current_context = next(context for context in contexts if context['name'] == kubeconfig['current-context'])
    user_name = current_context['context']['user']
    user = next(user for user in kubeconfig['users'] if user['name'] == user_name)
    
    if 'client-certificate' in user['user'] and 'client-key' in user['user']:
        client_certificate = user['user']['client-certificate']
        client_key = user['user']['client-key']
        return client_certificate, client_key
    else:
        raise ValueError("No valid client certificate authentication method found in kubeconfig.")
