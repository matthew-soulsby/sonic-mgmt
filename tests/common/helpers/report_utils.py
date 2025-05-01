from pytest import ExceptionInfo, TestReport


def analyze_ptf_failure(report: TestReport, exception_info: ExceptionInfo):
    # report_str = report.longreprtext
    # traceback = exception_info.traceback

    # Unable to connect to port 22

    # Feature '*' does not exist

    # ModuleNotFoundError

    # Packet arrived on wrong port

    # gNMI - Connection refused

    # gNMI - Heartbeat Deadline Exceeded

    # show intf - Permission denied

    # SSH Timeout - waiting for privilege escalation

    # config reload failed

    # exabgp exited too quickly

    # Copp policer constraint check failed (PPS range)

    # apt-get: Target packges configured multiple times

    # Did not receive expected packet on any ports

    # ecmp & lag hash balancing

    # reboot: port channel/peer devices failed probe

    return """Uncategorised PTF failure.
Please refer to the test output to determine the cause of the failure,
and consider enhancing the analyze_ptf_failure to provide a proper
recommendation."""
