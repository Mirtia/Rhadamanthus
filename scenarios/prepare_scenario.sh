#!/bin/bash
set -e
# For all scenarios, Clueless-Admin will be used to monitor the VM (in-guest monitoring).
# For each scenario, different (processes/modules) may need to (start/be loaded).

# Start Clueless-Admin using DRAKVUF. The linux-5.15.0-139.json was generated using dwarf2json.
# The default time window for the introspection is 5 minutes with sampling every 50 seconds (6 samples).
# These parameters were chosen to not overload the VM with logs, for now.

# We inject to process 1 (init) to start Clueless-Admin.
# The process has admin privileges so the Clueless-Admin will also have admin privileges.
# Wait for successful injection before starting introspector.

# Add domain ID as argument to the script and also add default value 2
DOMAIN_ID=${1:-2}
echo "Injecting to domain ID: ${DOMAIN_ID}"

echo "Starting Clueless-Admin injection..."
if sudo injector -r ../config/linux-5.15.0-139.json -d ${DOMAIN_ID} -m execproc -i 1 -e /usr/bin/clueless-admin -f "--all"; then
    echo "Injection (start-up) successful! Starting introspector..."
    sleep 3 # There is a delay startup that causes unhandled VMI events because of Drakvuf injection. (This needs investigation.)
    sudo ../build/introspector -c config/diamorphine.yaml
else
    echo "Injection failed. Exiting..."
    exit 1
fi

