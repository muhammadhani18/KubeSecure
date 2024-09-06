# Get all namespaces in the cluster
${namespaces} = kubectl get namespaces -o json | ConvertFrom-Json | Select-Object -ExpandProperty items | Select-Object -ExpandProperty metadata | Select-Object -ExpandProperty name

# Iterate through namespaces and fetch logs
foreach (${namespace} in ${namespaces}) {
    Write-Host "Namespace: ${namespace}"
    ${pods} = kubectl get pods --namespace=${namespace} -o json | ConvertFrom-Json | Select-Object -ExpandProperty items | Select-Object -ExpandProperty metadata | Select-Object -ExpandProperty name

    foreach (${pod} in ${pods}) {
        Write-Host "Pod: ${pod}"
        $containers = kubectl get pod ${pod} --namespace=${namespace} -o json | ConvertFrom-Json | Select-Object -ExpandProperty spec | Select-Object -ExpandProperty containers | Select-Object -ExpandProperty name
        
        foreach (${container} in ${containers}) {
            Write-Host "Container: $container"
            ${logs} = kubectl logs ${pod} -c ${container} --namespace=${namespace}
            # Filter logs for "echo hello"
            ${filteredLogs} = ${logs} | Select-String "echo hello"
            if (${filteredLogs}) {
                Write-Host "Logs for Container $container in Pod ${pod} in Namespace ${namespace}:\n"
                Write-Host ${filteredLogs}
            } else {
                Write-Host "No logs found for 'echo hello' in Container ${container} in Pod ${pod} in Namespace ${namespace}.\n"
            }
        }
    }
}
