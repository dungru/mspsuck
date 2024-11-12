# -*- coding: utf-8 -*-
import logging
import subprocess

from apis.openwrt.errors import OpenwrtError


class Dut(object):
    def __init__(self, adhoc, host, handler_chain):
        self.ipaddr = host.vars["ansible_host"]
        self.name = host.name
        self.vars = host.vars.get("vars", dict())
        self.telnet_server = host.vars.get("telnet_server")
        self.telnet_port = host.vars.get("telnet_port")
        self.username = (
            host.vars.get("username")
            if host.vars.get("username")
            else adhoc.group_vars.get("ansible_ssh_user")
        )
        self.password = (
            host.vars.get("password")
            if host.vars.get("password")
            else adhoc.group_vars.get("ansible_ssh_pass")
        )
        self.namespace_name = host.vars.get("namespace_name")
        self.remote_host = host.vars.get("remote_host")
        self.remote_user = host.vars.get("remote_user")

        self.__adhoc = adhoc
        self.__handler_chain = []
        self.__handler = None
        self.__info = None
        self.__ports = None
        self.__resources = None
        self.__port_status_changed = False
        self.__grpc_stub = None
        self.__board_info = None
        self.__port_map = {}
        self.__chip_config = {}

        # handler = None
        # for h in handler_chain:
        #     handler_class = getattr(handlers, h)
        #     self.__handler_chain.append(handler_class)
        #     next_handler = handler_class(self)

        #     if self.__handler is None:
        #         self.__handler = next_handler

        #     if handler is not None:
        #         handler.set_next(next_handler)

        #     handler = next_handler

    def shell(self, cmd, **kwargs):
        clear_log_result = self.__adhoc.run([self.name], "raw", "dmesg -c", **kwargs)
        if clear_log_result[self.name].failed:
            print(f"Failed to clear kernel log: {clear_log_result[self.name].stderr}")

        result = self.__adhoc.run([self.name], "raw", cmd, **kwargs)

        kernel_log_result = self.__adhoc.run([self.name], "raw", "dmesg -c", **kwargs)
        kernel_log = kernel_log_result[self.name].stdout if not kernel_log_result[self.name].failed else "Failed to retrieve kernel log"

        if result[self.name].failed:
            raise OpenwrtError(
                f"Error occurred while execute shell commands on "
                f"{self.name}\n"
                f"command: {cmd}\n"
                f"return_code: {result[self.name].rc}\n"
                f"stdout: {result[self.name].stdout}\n"
                f"stderr: {result[self.name].stderr}\n"
                f"kernel_log: {kernel_log}"
            )

        return result[self.name].stdout.strip(), kernel_log.strip()

    def exec_cmd(self, cmd):
        """Helper method to execute a command and return the output."""
        try:
            result = subprocess.run(cmd, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            return result.stdout.strip()
        except subprocess.CalledProcessError as e:
            logging.error(f"Command failed: {self.name}: {cmd}\nError: {e.stderr.strip()}")
            raise OpenwrtError(f"Command execution failed: {e.stderr.strip()}")

    def shell_local_ns(self, cmd, **kwargs):
        """Execute a command in a local network namespace via SSH."""
        # Clear the kernel log
        clear_log_cmd = f"sudo ip netns exec {self.namespace_name} ssh -o StrictHostKeyChecking=no -o HostKeyAlgorithms=+ssh-rsa {self.remote_user}@{self.remote_host} 'dmesg -c'"
        self.exec_cmd(clear_log_cmd)

        # Execute the provided command
        command_to_run = f"sudo ip netns exec {self.namespace_name} ssh -o StrictHostKeyChecking=no -o HostKeyAlgorithms=+ssh-rsa {self.remote_user}@{self.remote_host} '{cmd};dmesg -c'"
        return self.exec_cmd(command_to_run)

    def shell_ns(self, cmd, **kwargs):
        clear_log_result = self.__adhoc.run_ns([self.name], "shell", "dmesg -c", **kwargs)
        if clear_log_result[self.name].failed:
            print(f"Failed to clear kernel log: {clear_log_result[self.name].stderr}")

        result = self.__adhoc.run_ns([self.name], "shell", cmd, **kwargs)

        kernel_log_result = self.__adhoc.run([self.name], "shell", "dmesg -c", **kwargs)
        kernel_log = kernel_log_result[self.name].stdout if not kernel_log_result[self.name].failed else "Failed to retrieve kernel log"

        if result[self.name].failed:
            raise OpenwrtError(
                f"Error occurred while execute shell commands on "
                f"{self.name}\n"
                f"command: {cmd}\n"
                f"return_code: {result[self.name].rc}\n"
                f"stdout: {result[self.name].stdout}\n"
                f"stderr: {result[self.name].stderr}\n"
                f"kernel_log: {kernel_log}"
            )

        return result[self.name].stdout.strip(), kernel_log.strip()
