from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from ironclad import remediation as repair, actions
from ironclad.storage import Store


class RepairTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.state=Path(self.temp.name)/'state'
        self.value='0'
        self.read=patch('ironclad.remediation.aslr_value',side_effect=lambda:self.value)
        self.read.start();self.addCleanup(self.read.stop)
        self.auth=patch('ironclad.remediation.authenticate',return_value=0)
        self.auth.start();self.addCleanup(self.auth.stop)

    def plan(self):return repair.make_plan('security.enable-aslr')

    def test_options_are_read_only_and_show_exact_impact_undo_verification(self):
        with patch('ironclad.remediation.run_command') as run:
            data=repair.options('security.kernel.aslr')
        plan=data['plans'][0]
        self.assertEqual(plan['commands'],[['/usr/bin/sysctl','-w','kernel.randomize_va_space=2']])
        self.assertIn('=0',plan['undo'])
        self.assertTrue(plan['impact']);self.assertTrue(plan['verification'])
        run.assert_not_called()

    def test_unsupported_and_firmware_checks_are_manual(self):
        for check in ('unknown.check','security.boot.secure_boot'):
            data=repair.options(check)
            self.assertFalse(data['plans']);self.assertTrue(data['manual'])

    def test_protected_tpm_and_session_units_never_offer_retry(self):
        with patch('ironclad.remediation.failed_services',return_value=['systemd-pcrproduct.service','sshd.service','omarchy-shell.service']):
            data=repair.options('startup.units.system_failed')
        self.assertEqual(data['plans'],[])
        self.assertIn('systemd-pcrproduct.service',data['manual'])

    def test_service_names_cannot_be_flags_paths_or_shell(self):
        for name in ('--all','/tmp/x.service','a.service;id','a.service\nfoo','systemd-pcrproduct.service'):
            with self.assertRaises(ValueError):repair.make_plan('service.retry-system',name)

    def test_missing_wrong_expired_and_tampered_approval_refused(self):
        plan=self.plan()
        for approval in (None,'a'*64):
            with self.assertRaises(ValueError):repair.queue(self.state,plan,approval)
        for altered in (dict(plan,commands=[['/usr/bin/rm','-rf','/']]),dict(plan,created=plan['created']-181)):
            altered['digest']=repair.digest(altered)
            with self.assertRaises(ValueError):repair.queue(self.state,altered,altered['digest'])

    def test_changed_precondition_refused_before_queue(self):
        plan=self.plan();self.value='1'
        with self.assertRaises(ValueError):repair.queue(self.state,plan,plan['digest'])

    def test_queue_never_executes_and_ticket_is_private(self):
        plan=self.plan()
        with patch('ironclad.remediation.run_command') as run:
            ticket=repair.queue(self.state,plan,plan['digest'])['ticket']
        run.assert_not_called()
        path=repair.ticket_path(self.state,ticket,'.request.json')
        self.assertEqual(path.stat().st_mode&0o777,0o600)

    def test_success_executes_only_reviewed_command_and_verifies(self):
        plan=self.plan();ticket=repair.queue(self.state,plan,plan['digest'])['ticket']
        def apply(command,privileged):
            self.assertEqual(command,plan['commands'][0]);self.assertTrue(privileged)
            self.value='2';return 0
        with patch('ironclad.remediation.run_command',side_effect=apply) as run:
            result=repair.run_ticket(self.state,ticket,plan['digest'])
        self.assertTrue(result['verified']);self.assertTrue(result['applied']);run.assert_called_once()
        self.assertEqual(repair.result(self.state,ticket),result)

    def test_auth_cancel_or_manager_failure_never_claims_success(self):
        for code in (1,7):
            plan=self.plan();ticket=repair.queue(self.state,plan,plan['digest'])['ticket']
            with patch('ironclad.remediation.run_command',return_value=code):
                result=repair.run_ticket(self.state,ticket,plan['digest'])
            self.assertFalse(result['verified']);self.assertEqual(result['exit_code'],code)

    def test_command_success_without_postcondition_stays_unverified(self):
        plan=self.plan();ticket=repair.queue(self.state,plan,plan['digest'])['ticket']
        with patch('ironclad.remediation.run_command',return_value=0):
            result=repair.run_ticket(self.state,ticket,plan['digest'])
        self.assertTrue(result['applied']);self.assertFalse(result['verified'])
        self.assertIn('did not report',result['message'])

    def test_precondition_changes_after_queue_do_not_execute(self):
        plan=self.plan();ticket=repair.queue(self.state,plan,plan['digest'])['ticket'];self.value='1'
        with patch('ironclad.remediation.run_command') as run:
            result=repair.run_ticket(self.state,ticket,plan['digest'])
        run.assert_not_called();self.assertFalse(result['verified'])

    def test_ticket_cannot_be_replayed(self):
        plan=self.plan();ticket=repair.queue(self.state,plan,plan['digest'])['ticket']
        with patch('ironclad.remediation.run_command',return_value=7):repair.run_ticket(self.state,ticket,plan['digest'])
        with patch('ironclad.remediation.run_command') as run:
            with self.assertRaises(FileExistsError):repair.run_ticket(self.state,ticket,plan['digest'])
        run.assert_not_called()

    def test_symlinked_request_and_path_ticket_refused(self):
        plan=self.plan();ticket=repair.queue(self.state,plan,plan['digest'])['ticket']
        request=repair.ticket_path(self.state,ticket,'.request.json');request.unlink();request.symlink_to('/etc/passwd')
        with patch('ironclad.remediation.run_command') as run:result=repair.run_ticket(self.state,ticket,plan['digest'])
        self.assertFalse(result['verified']);run.assert_not_called()
        with self.assertRaises(ValueError):repair.result(self.state,'../elsewhere')

    def test_interruption_records_unverified_receipt(self):
        plan=self.plan();ticket=repair.queue(self.state,plan,plan['digest'])['ticket']
        with patch('ironclad.remediation.run_command',side_effect=SystemExit(130)):
            with self.assertRaises(SystemExit):repair.run_ticket(self.state,ticket,plan['digest'])
        self.assertFalse(repair.result(self.state,ticket)['verified'])

    def test_home_permission_repair_and_exact_target_undo_use_temp_home(self):
        home=Path(self.temp.name)/'home';home.mkdir();home.chmod(0o702)
        with patch('ironclad.actions.account_home',return_value=home):
            plan=repair.make_plan(actions.ACTION_ID)
            self.assertTrue(all(isinstance(value,str) for value in plan['before']))
            self.assertIsInstance(plan['created'],int)
            ticket=repair.queue(self.state,plan,plan['digest'])['ticket']
            result=repair.run_ticket(self.state,ticket,plan['digest'])
            self.assertTrue(result['verified']);self.assertEqual(home.stat().st_mode&0o777,0o700)
            store=Store(self.state)
            try:actions.rollback(store,result['undo_receipt'])
            finally:store.close()
            self.assertEqual(home.stat().st_mode&0o777,0o702)

    def test_service_retry_requires_new_successful_invocation(self):
        before={'Id':'demo.service','LoadState':'loaded','ActiveState':'failed','SubState':'failed','Result':'exit-code','Type':'simple','InvocationID':'old'}
        with patch('ironclad.remediation.failed_services',return_value=['demo.service']),patch('ironclad.remediation.service',return_value=before):
            plan=repair.make_plan('service.retry-user','demo.service')
        for invocation,expected in (('old',False),('new',True)):
            after=dict(before,ActiveState='active',Result='success',InvocationID=invocation)
            with patch('ironclad.remediation.service',return_value=after):self.assertEqual(repair.verify(plan)[0],expected)

    def test_discovery_review_is_specific_and_other_listeners_prevent_resolution(self):
        active={'Id':'avahi-daemon.service','LoadState':'loaded','ActiveState':'active'}
        with patch('ironclad.remediation.service',return_value=active),patch('ironclad.remediation.discovery_listeners',return_value=True):
            plan=repair.make_plan('network.stop-discovery')
        self.assertEqual(plan['commands'],[['/usr/bin/systemctl','stop','avahi-daemon.socket','avahi-daemon.service']])
        with patch('ironclad.remediation.service',return_value={'ActiveState':'inactive'}),patch('ironclad.remediation.wildcard_listeners',return_value=True):
            self.assertFalse(repair.verify(plan)[0])

    def test_enabled_time_sync_without_synchronized_clock_is_not_verified(self):
        with patch('ironclad.remediation.ntp_value',return_value='no'):plan=repair.make_plan('clock.enable-sync')
        with patch('ironclad.remediation.ntp_value',return_value='yes'),patch('ironclad.remediation.query',return_value='no'):
            self.assertFalse(repair.verify(plan)[0])

    def test_cancelled_admin_authentication_runs_no_repair(self):
        plan=self.plan();ticket=repair.queue(self.state,plan,plan['digest'])['ticket']
        with patch('ironclad.remediation.authenticate',return_value=1),patch('ironclad.remediation.run_command') as run:
            result=repair.run_ticket(self.state,ticket,plan['digest'])
        self.assertFalse(result['verified']);run.assert_not_called()
        self.assertIn('No repair command',result['message'])

    def test_state_change_while_entering_password_is_refused(self):
        plan=self.plan();ticket=repair.queue(self.state,plan,plan['digest'])['ticket']
        def authenticate():self.value='1';return 0
        with patch('ironclad.remediation.authenticate',side_effect=authenticate),patch('ironclad.remediation.run_command') as run:
            result=repair.run_ticket(self.state,ticket,plan['digest'])
        self.assertFalse(result['verified']);run.assert_not_called()

    def test_discovery_fix_not_offered_for_unrelated_open_port(self):
        active={'Id':'avahi-daemon.service','LoadState':'loaded','ActiveState':'active'}
        with patch('ironclad.remediation.service',return_value=active),patch('ironclad.remediation.discovery_listeners',return_value=False):
            self.assertEqual(repair.options('network.listeners')['plans'],[])
