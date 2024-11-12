# -*- coding: utf-8 -*-
import json

from ansible import context
from ansible.errors import AnsibleError
from ansible.executor.task_queue_manager import TaskQueueManager
from ansible.inventory.manager import InventoryManager
from ansible.module_utils.common.collections import ImmutableDict
from ansible.parsing.dataloader import DataLoader
from ansible.playbook.play import Play
from ansible.plugins.callback import CallbackBase
from ansible.vars.manager import VariableManager
from pyrsistent import freeze

from apis.utils import AttrDict


class ResultsCallback(CallbackBase):
    """
    A sample callback plugin used for performing an action as results come in.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.contacted = AttrDict()
        self.unreachable = AttrDict()

    def v2_runner_on_failed(self, result, *args, **kwargs):
        failed = AttrDict(ok=False, failed=True)
        failed.update(result._result)
        self.contacted[result._host.name] = failed

    def v2_runner_on_ok(self, result):
        ok = AttrDict(ok=True, failed=False)
        ok.update(result._result)
        self.contacted[result._host.name] = ok

    def v2_runner_on_unreachable(self, result):
        self.unreachable[result._host.name] = AttrDict(result._result)


class AdHoc(object):
    def __init__(self, inventory_file, vault_pass=""):
        # initialize needed objects
        self.__loader = DataLoader()
        self.__inv_mgr = InventoryManager(
            loader=self.__loader, sources=inventory_file
        )
        self.__var_mgr = VariableManager(
            loader=self.__loader, inventory=self.__inv_mgr
        )
        self.__passwords = dict(vault_pass=vault_pass)

    @property
    def group_vars(self):
        return freeze(self.__inv_mgr.groups["topology"].vars)

    @property
    def hosts(self):
        return freeze(self.__inv_mgr.groups["topology"].hosts)

    def run(self, hosts, module_name, *args, **kwargs):
        rc = ResultsCallback()
        tqm = TaskQueueManager(
            inventory=self.__inv_mgr,
            variable_manager=self.__var_mgr,
            loader=self.__loader,
            passwords=self.__passwords,
            stdout_callback=rc,
        )

        ori_cliargs = context.CLIARGS
        tmp_cliargs = dict(ori_cliargs)
        for arg_name in (
            "connection",
            "user",
            "become",
            "become_method",
            "become_user",
            "module_path",
        ):
            v = kwargs.pop(arg_name, None)
            v and tmp_cliargs.update({arg_name: v})
        # Assemble module argument string
        if args:
            kwargs.update(dict(_raw_params=" ".join(args)))
        # create data structure that represents our play, including tasks, this is basically what our YAML loader does internally.
        play_source = dict(
            name="pytest-ansible",
            hosts=hosts,
            gather_facts='no',
            tasks=[
                dict(action=dict(module=module_name, args=kwargs))
            ]
        )

        # Create play object, playbook objects use .load instead of init or new methods,
        # this will also automatically create the task objects from the info provided in play_source
        play = Play().load(play_source, variable_manager=self.__var_mgr, loader=self.__loader)
        context.CLIARGS = ImmutableDict(tmp_cliargs)
        # Actually run it
        try:
            tqm.run(play)  # most interesting data for a play is actually sent to the callback's methods
        finally:
            # Always need to cleanup child procs and the structures we use
            # to communicate with them.
            context.CLIARGS = ori_cliargs
            tqm.cleanup()
            self.__loader.cleanup_all_tmp_files()

        if rc.unreachable:
            raise AnsibleError(
                f"Host unreachable\n{json.dumps(rc.unreachable)}"
            )

        return rc.contacted

    def run_ns(self, hosts, module_name, *args, **kwargs):
        rc = ResultsCallback()
        tqm = TaskQueueManager(
            inventory=self.__inv_mgr,
            variable_manager=self.__var_mgr,
            loader=self.__loader,
            passwords=self.__passwords,
            stdout_callback=rc,
        )
        ori_cliargs = context.CLIARGS
        tmp_cliargs = dict(ori_cliargs)

        # Extract become and become_user from kwargs
        become = kwargs.pop('become', 'yes')  # Default to 'yes' if not provided
        become_user = kwargs.pop('become_user', 'dutsai')  # Default to 'dutsai' if not provided

        # Update tmp_cliargs with become and become_user
        tmp_cliargs.update({
            'become': become,
            'become_user': become_user,
        })

        for arg_name in (
            "connection",
            "user",
            "become",
            "become_method",
            "become_user",
            "module_path",
        ):
            v = kwargs.pop(arg_name, None)
            v and tmp_cliargs.update({arg_name: v})
        # Extract variables from kwargs or set defaults
        namespace_name = "pc1"  # Default namespace name
        remote_user = "root"  # Default remote user
        remote_host = "192.168.99.110"  # Default to localhost
        # Assemble module argument string
        if args:
            remote_command = " ".join(args)  # Join the remaining args as the command
            command_to_run = f"sudo ip netns exec {namespace_name} ssh -o StrictHostKeyChecking=no -o HostKeyAlgorithms=+ssh-rsa {remote_user}@{remote_host} '{remote_command}'"
            kwargs.update(dict(_raw_params=command_to_run))
        # create data structure that represents our play, including tasks, this is basically what our YAML loader does internally.
        play_source = dict(
            name="Execute command in network namespace",
            hosts=hosts,
            gather_facts='no',
            vars={
                'namespace_name': namespace_name,
                'remote_host': remote_host,
                'remote_user': remote_user,
            },
            tasks=[
                dict(action=dict(module=module_name, args=kwargs))
            ]
        )
        # Create play object, playbook objects use .load instead of init or new methods,
        # this will also automatically create the task objects from the info provided in play_source
        play = Play().load(play_source, variable_manager=self.__var_mgr, loader=self.__loader)
        context.CLIARGS = ImmutableDict(tmp_cliargs)
        # Actually run it
        try:
            tqm.run(play)  # most interesting data for a play is actually sent to the callback's methods
        finally:
            # Always need to cleanup child procs and the structures we use
            # to communicate with them.
            context.CLIARGS = ori_cliargs
            tqm.cleanup()
            self.__loader.cleanup_all_tmp_files()

        if rc.unreachable:
            raise AnsibleError(
                f"Host unreachable\n{json.dumps(rc.unreachable)}"
            )

        return rc.contacted
