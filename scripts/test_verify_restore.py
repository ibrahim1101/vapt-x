"""Guard tests never contact Docker or MongoDB."""
import unittest
from unittest.mock import Mock
from pymongo.errors import OperationFailure
from verify_restore import validate_environment, database_names, command, cleanup_owned

CONTAINER = 'a' * 64
ENV = {'GITHUB_ACTIONS': 'true', 'RESTORE_TEST_URI': 'mongodb://127.0.0.1:27017', 'RESTORE_TEST_CONTAINER': CONTAINER}


class RestoreGuardTests(unittest.TestCase):
    def test_reject_remote_authenticated_options_and_database_uris(self):
        for uri in ('mongodb://example.com:27017', 'mongodb://127.0.0.1:27017/customer',
                    'mongodb://user:pass@127.0.0.1:27017', 'mongodb://@127.0.0.1:27017',
                    'mongodb://127.0.0.1:27017/?authSource=admin', 'mongodb+srv://localhost',
                    'mongodb://127.0.0.1:27017,localhost:27017', 'mongodb://127.0.0.1:27017/#fragment',
                    'mongodb://127.0.0.1:27017/\n', 'mongodb://127.0.0.1:27017/%2f'):
            with self.subTest(uri=uri), self.assertRaises(ValueError):
                validate_environment({**ENV, 'RESTORE_TEST_URI': uri})

    def test_requires_ci_and_exact_container(self):
        for overrides in ({'GITHUB_ACTIONS': 'false'}, {'RESTORE_TEST_CONTAINER': 'mongo'},
                          {'RESTORE_TEST_CONTAINER': '--privileged'}, {'RESTORE_TEST_CONTAINER': ''}):
            with self.subTest(overrides=overrides), self.assertRaises(ValueError):
                validate_environment({**ENV, **overrides})
        self.assertEqual(validate_environment(ENV), (ENV['RESTORE_TEST_URI'], 27017, CONTAINER))

    def test_only_generated_names_and_narrow_remap_arguments(self):
        source, restored = database_names()
        self.assertNotEqual(source, restored)
        args = command(CONTAINER, 'restore', source, restored)
        self.assertEqual(args[:4], ['docker', 'exec', '-i', CONTAINER])
        for value in ('--archive', '--gzip', '--nsInclude=' + source + '.*', '--nsFrom=' + source + '.*', '--nsTo=' + restored + '.*'):
            self.assertIn(value, args)
        self.assertNotIn('--drop', args)
        for bad in ('production', '--drop', 'vaptx_restore_test_customer', source + ';echo'):
            with self.assertRaises(ValueError):
                command(CONTAINER, 'restore', bad, restored)
        with self.assertRaises(ValueError):
            command(CONTAINER, 'restore', source, source)

    def test_cleanup_requires_marker_and_exact_generated_names(self):
        client = Mock()
        source, restored = database_names()
        client.__getitem__ = Mock()
        client.__getitem__.return_value.drill_owner.find_one.side_effect = [None, {'synthetic': True}]
        cleanup_owned(client, [source, restored], 'owner')
        client.drop_database.assert_called_once_with(restored)
        with self.assertRaises(ValueError):
            cleanup_owned(client, ['customer'], 'owner')

    def test_cleanup_attempts_second_namespace_after_first_failure(self):
        for failure_at in ('lookup', 'drop'):
            with self.subTest(failure_at=failure_at):
                client = Mock()
                source, restored = database_names()
                client.__getitem__ = Mock()
                marker = client.__getitem__.return_value.drill_owner.find_one
                marker.side_effect = ([OperationFailure('synthetic failure'), {'synthetic': True}]
                                      if failure_at == 'lookup' else [{'synthetic': True}] * 2)
                client.drop_database.side_effect = ([OperationFailure('synthetic failure'), None]
                                                    if failure_at == 'drop' else None)
                with self.assertRaisesRegex(RuntimeError, 'cleanup failed'):
                    cleanup_owned(client, [source, restored], 'owner')
                self.assertEqual(marker.call_count, 2)
                self.assertEqual(client.drop_database.call_args.args, (restored,))


if __name__ == '__main__':
    unittest.main()
