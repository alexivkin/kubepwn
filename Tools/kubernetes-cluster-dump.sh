#!/usr/bin/env bash

set -e

CONTEXT="$1"

if [[ -z ${CONTEXT} ]]; then
  echo "Usage: $0 <KUBE-CONTEXT>"
  echo "One of:"
  kubectl config get-contexts
  exit 1
fi

#mkdir -p "${CONTEXT}"
echo -n "Native export to jsons..."
# the  -o yaml flag will create yaml exports but name them .json in 1.15.1
kubectl --context ${CONTEXT} cluster-info dump --all-namespaces --output-directory=${CONTEXT}/cluster-info-dump/

NAMESPACES=$(kubectl --context ${CONTEXT} get -o json namespaces|jq '.items[].metadata.name'|sed "s/\"//g")
#RESOURCES="configmap secret daemonset deployment service hpa"
GLOBAL_RESOURCES=$(kubectl api-resources --namespaced=false -o name)
RESOURCES=$(kubectl api-resources --namespaced=true -o name)

echo -n "Counting non-namespaced resources to yamls..."

globalcount=0
for resource in ${GLOBAL_RESOURCES}; do
  rsrcs=$(kubectl --context ${CONTEXT} get -o json ${resource} 2>/dev/null | jq '.items[].metadata.name'|sed "s/\"//g" )
  if [[ ! -z "${rsrcs}" ]]; then # to avoid counting empty lines
    rsrcscount=$(echo "${rsrcs}" | wc -l)
    globalcount=$(( globalcount + rsrcscount ))
  fi
  # else add to the skip list so we dont waste time on it during the export
done
echo "$globalcount. Exporting..."

for resource in ${GLOBAL_RESOURCES}; do
  #echo "Global resource $resource"
  rsrcs=$(kubectl --context ${CONTEXT} get -o json ${resource}  2>/dev/null | jq '.items[].metadata.name'|sed "s/\"//g" )
  for r in ${rsrcs}; do
    echo "   Name $resource/$r"
    dir="${CONTEXT}/global-resources-yaml/${resource}"
    mkdir -p "${dir}"
    kubectl --context ${CONTEXT} get -o yaml ${resource} ${r} > "${dir}/${r}.yaml"
  done
done | pv -pl -s $globalcount  > /dev/null

echo -n "Counting namespaced resources to yamls..."

localcount=0
for ns in ${NAMESPACES}; do
  for resource in ${RESOURCES}; do
    rsrcs=$(kubectl --context ${CONTEXT} -n ${ns} get -o json ${resource} 2>/dev/null | jq '.items[].metadata.name'|sed "s/\"//g")
    if [[ ! -z "${rsrcs}" ]]; then # to avoid counting empty lines
      rsrcscount=$(echo "${rsrcs}" | wc -l)
      localcount=$(( localcount + rsrcscount ))
    fi
  done
done
echo "$localcount. Exporting..."

for ns in ${NAMESPACES}; do
  #echo "Namespace $ns"
  for resource in ${RESOURCES}; do
    #echo "   Resource $resource"
    rsrcs=$(kubectl --context ${CONTEXT} -n ${ns} get -o json ${resource}  2>/dev/null | jq '.items[].metadata.name'|sed "s/\"//g")
    for r in ${rsrcs}; do
      echo "      Name $ns/$resource/$r"
      dir="${CONTEXT}/namespaces-yaml/${ns}/${resource}"
      mkdir -p "${dir}"
      kubectl --context ${CONTEXT} -n ${ns} get -o yaml ${resource} ${r} > "${dir}/${r}.yaml"
    done
  done
done | pv -pl -s $localcount  > /dev/null
