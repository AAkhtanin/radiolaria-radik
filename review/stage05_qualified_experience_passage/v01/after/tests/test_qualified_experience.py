"""Short data-boundary controls; fixtures do not claim native owner execution."""
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from app import qualified_experience as experience
from app import qualified_experience_work as pure
from app.native_authority import digest


def material(text):
    source = dict(source_ref='radik:source:' + 'a' * 32, revision=1, sha256=digest(text.encode()),
        text=text, observed_at=1792454400)
    descriptor = {key:source[key] for key in ('source_ref', 'revision', 'sha256')}
    return dict(version='radik.qualified_material.v01', scope_sha256='b' * 64,
        accepted_result_sha256='c' * 64, checks=[dict(semantic_ref='fixture:claim',
            observations=[dict(observation_id='radik:observation:' + digest(descriptor), source=source)])])


class QualifiedExperienceTests(unittest.TestCase):
    def test_actual_negative_predicate_produces_a_bound_extra_audit(self):
        supplied = material('Fictional support is included. The price of calls is not specified.')
        verification = pure.compute(supplied, pure.VERIFY)
        audit = pure.compute(supplied, pure.AUDIT)
        self.assertIs(verification['checks'][0]['healthy'], False)
        self.assertEqual(audit['input_sha256'], digest(supplied))
        self.assertEqual(verification['input_sha256'], digest(supplied))
        self.assertEqual(audit['finding_count'], 1)
        self.assertEqual(audit['next_review'], 'CHECK_UNRESOLVED_SOURCE_CONDITIONS')
        finding = audit['findings'][0]
        source = supplied['checks'][0]['observations'][0]['source']
        self.assertEqual(source['text'].encode()[finding['start']:finding['end']].decode(), finding['quote'])
        self.assertEqual(finding['quote'], 'not specified')
        self.assertNotIn('findings', verification)

    def test_no_marker_is_not_an_external_truth_claim(self):
        result = pure.compute(material('Fictional support is included at a listed cost of five units.'), pure.VERIFY)
        self.assertIs(result['checks'][0]['healthy'], True)
        self.assertEqual(result['qualified_scope'],
            'Approved raw source markers only; no external truth or model quality claim.')

    def test_source_or_lineage_changes_are_not_silently_consumed(self):
        for mutation in ('raw_bytes', 'revision', 'observation_ref', 'extra_field'):
            with self.subTest(mutation=mutation):
                value = material('Unknown call prices need another check.')
                source = value['checks'][0]['observations'][0]['source']
                if mutation == 'raw_bytes':
                    source['text'] = 'All prices are confirmed.'
                elif mutation == 'revision':
                    source['revision'] += 1
                elif mutation == 'observation_ref':
                    value['checks'][0]['observations'][0]['observation_id'] = 'forged'
                else:
                    value['creates_permission'] = True
                with self.assertRaises(ValueError):
                    pure.compute(value, pure.VERIFY)

    def test_prospective_persistence_has_exact_readback_and_never_overwrites(self):
        with TemporaryDirectory(delete=False) as directory:
            service = experience.QualifiedExperience(Path(directory) / 'evidence')
            value = dict(claim='EXPECT_NO_UNRESOLVED_MARKERS', expected_fp=500000000)
            receipt = service._persist('prospective', value)
            path = service.directory / ('prospective_' + digest(value) + '.json')
            self.assertEqual(path.read_bytes(), experience.canonical(value))
            self.assertEqual(receipt['sha256'], digest(path.read_bytes()))
            path.write_bytes(b'{}')
            with self.assertRaisesRegex(ValueError, 'experience_evidence_collision'):
                service._persist('prospective', value)
            self.assertEqual(path.read_bytes(), b'{}')

    def test_unscorable_transport_preserves_qualified_history(self):
        class Spec:
            task_id = 'fixture:unscorable'
        class Controller:
            spec = Spec()
        with TemporaryDirectory(delete=False) as directory:
            service = experience.QualifiedExperience(Path(directory) / 'evidence')
            report = service.audit_unscorable(Controller(), 'TRANSPORT_FAILURE')
            self.assertEqual(report['update_eligibility'], 'NO_UPDATE')
            self.assertIsNone(report['observed_result'])
            self.assertEqual(report['task_outcome'], 'UNKNOWN')
            self.assertEqual(report['qualified_history_before'], {})
            self.assertEqual(report['qualified_history_after'], {})
            self.assertEqual(service._events, {})
            self.assertEqual(service._captures, [])

    def test_plain_json_cannot_be_a_current_qualified_binding(self):
        with self.assertRaisesRegex(ValueError, 'experience_binding_origin'):
            experience.validate_strategy_history(None, dict(prior_fp=-62500000, trusted=True))


if __name__ == '__main__':
    unittest.main()
