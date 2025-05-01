import re

from typing import Optional, cast

from pytest import ExceptionInfo, TestReport

from tests.common.devices.eos import EosHost
from tests.common.devices.ptf import PTFHost
from tests.common.devices.sonic import SonicHost


def extract_info_from_traceback(req: dict[str, type], exception_info: ExceptionInfo):
    res = {}

    # Check at each level of traceback
    for entry in exception_info.traceback:
        raw_frame = entry.frame.raw
        locals_at_frame = raw_frame.f_locals

        # Check each remaining requested value
        for name, val_type in req.items():
            if name in locals_at_frame:
                val = locals_at_frame[name]
                if isinstance(val, val_type):
                    # Store this value
                    res[name] = val

                    # Stop searching for it
                    req.pop(name)

    return res


def analyze_failure(report: TestReport, exception_info: ExceptionInfo):
    err_msg = str(exception_info.value)
    info = extract_info_from_traceback({
        'self': EosHost,
        'ptfhost': PTFHost,
        'duthost': SonicHost,
    }, exception_info)

    eos_host = cast(Optional[EosHost], info.get('self'))
    ptf_host = cast(Optional[PTFHost], info.get('ptfhost'))
    dut_host = cast(Optional[SonicHost], info.get('duthost'))

    # SSH unavailable - EoS host
    if "Unable to connect to port 22" in err_msg:
        if not eos_host:
            return """
                SSH was unreachable for the EoS host.

                Please check the reachability of this host from the device
                hosting the management container.
            """

        return f"""
            SSH was unreachable for the EoS host at IP {eos_host.mgmt_ip}.

            Please check the reachability of this host from the device
            hosting the management container.
        """

    # Feature '*' does not exist - SonicHost
    match = re.search(r"Feature '(\S+)' doesn't exist", err_msg)
    if match:
        feature = match.group(1)
        if not dut_host:
            return f"""
                DUT does not have the following feature: {feature}.

                Test case may not be appropriate for this device.
            """

        return f"""
            DUT '{dut_host.hostname}' does not have feature: {feature}.

            Test case may not be appropriate for this device.
        """

    # ModuleNotFoundError
    match = re.search(r"ModuleNotFoundError: No module named '(\S+)'", err_msg)
    if match:
        missing_module = match.group(1)
        if not ptf_host:
            return f"""
                PTF container is missing the following module: {missing_module}.

                Consider updating the relevant script/module to use the correct
                module,or updating the PTF container image to a version which
                contains this module.
            """
        return f"""
            PTF container ({ptf_host.hostname}, {ptf_host.mgmt_ip}) is missing
            the following module: {missing_module}.

            Consider updating the relevant script/module to use the correct
            module,or updating the PTF container image to a version which
            contains this module.
        """

    # Packet arrived on wrong port
    match = re.search(
        r"AssertionError: Received expected packet on port (\d+) for \
        device (\d+), but it should have arrived on one of these ports: [(.+)].",
        err_msg
    )
    if match:
        wrong_port = match.group(1)
        device_no = match.group(2)
        expected_ports = f"[{match.group(3)}]"

        if not dut_host or not ptf_host:
            return f"""
                PTF container received the packet on the incorrect port.

                The indexes of the interfaces on the DUT are:
                    - {wrong_port}
                    - {expected_ports}

                Check that the DUT's VLAN configuration is correct.
                Additionally, check with the lab team that the correct
                physical interfaces are connected to the correct interfaces
                on the fanout device.
            """

        return f"""
            PTF container {ptf_host.hostname} received the packet on the
            incorrect port.

            The indexes of the interfaces on the DUT are:
                - {wrong_port}
                - {expected_ports}

            Check that the DUT ({dut_host.hostname}, {device_no}) VLAN
            configuration is correct.

            Additionally, check with the lab team that the correct
            physical interfaces are connected to the correct interfaces
            on the fanout device.
            The index of the interfaces are: {wrong_port} and {expected_ports}
        """

    # gNMI - Connection refused
    if "socket.error: [Errno 111] Connection refused" in err_msg:
        if not dut_host:
            return """
                gNMI connection was refused by the socket on the device.

                Try to power cycle the device to start a new socket.
            """
        return f"""
            gNMI connection was refused by the socket on {dut_host.hostname}.

            Try to power cycle the device to start a new socket.
        """

    # gNMI - Heartbeat Deadline Exceeded
    if "status = StatusCode.DEADLINE_EXCEEDED" in err_msg:
        if not dut_host or not ptf_host:
            # Default message for cases where we could not get dut/ptf info
            return """
                gNMI heartbeat deadline exceeded.

                The DUT may be unreachable from the PTF container.
                Additionally, the gNMI container may be unhealthy.
            """

        dut_ip = dut_host.mgmt_ip
        ptf_ip = ptf_host.mgmt_ip
        return f"""
            gNMI heartbeat deadline exceeded.

            Check the reachability between the DUT (IP: {dut_ip}) and the
            PTF container (IP: {ptf_ip}).

            Additionally, check that the gNMI container is running as expected
            on the DUT (port 50051).
        """

    # show intf - Permission denied

    # SSH Timeout - waiting for privilege escalation

    # config reload failed

    # exabgp exited too quickly

    # Copp policer constraint check failed (PPS range)

    # apt-get: Target packges configured multiple times

    # Did not receive expected packet on any ports

    # ecmp & lag hash balancing

    # reboot: port channel/peer devices failed probe

    return """
        Uncategorised Ansible Module failure.

        Please refer to the test output to determine the cause of the failure,
        and consider enhancing the analyze_failure to provide a proper
        recommendation.
    """
