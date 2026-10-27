#!/bin/bash

set -euo pipefail

OVS_DPDK_CPUS="{{ .OvsDpdkCpus }}"
PARTITION_TYPE="{{ .PartitionType }}"

if [ -z "$OVS_DPDK_CPUS" ]; then
	echo "No OVS-DPDK CPUs configured, nothing to do"
	exit 0
fi

OVS_SLICE="/sys/fs/cgroup/ovs.slice"
VSWITCHD_CGROUP="${OVS_SLICE}/ovs-vswitchd.service"
OVSDPDK_SLICE="${VSWITCHD_CGROUP}/ovsdpdk.slice"

if [ ! -d "$OVS_SLICE" ]; then
	echo "ERROR: ovs.slice cgroup does not exist at $OVS_SLICE" >&2
	exit 1
fi

if [ ! -d "$VSWITCHD_CGROUP" ]; then
	echo "ERROR: ovs-vswitchd.service cgroup does not exist at $VSWITCHD_CGROUP" >&2
	exit 2
fi

# The ovs-vswitchd.service drop-in sets Delegate=cpuset cpu pids, so systemd
# enables those controllers in ovs.slice/cgroup.subtree_control automatically.
# We only need to enable them inside the delegated subtree.
echo "+cpuset +cpu +pids" > "$VSWITCHD_CGROUP/cgroup.subtree_control"

mkdir -p "$OVSDPDK_SLICE"
echo "threaded" > "$OVSDPDK_SLICE/cgroup.type"

for cg in "$OVS_SLICE" "$VSWITCHD_CGROUP" "$OVSDPDK_SLICE"; do
	echo "$OVS_DPDK_CPUS" > "$cg/cpuset.cpus.exclusive"
done
echo "$PARTITION_TYPE" > "$OVSDPDK_SLICE/cpuset.cpus.partition"

echo "Configured ovsdpdk.slice inside ovs-vswitchd.service as partition=$PARTITION_TYPE for CPUs: $OVS_DPDK_CPUS"
