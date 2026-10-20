"""Focused pure adapter checks; these fixtures are not owner/native evidence."""
import unittest

from app import qualified_strategy as strategy
from app.native_authority import digest


def basis(prior=0):
    text = 'Unknown exceptions remain unless the source confirms them.'
    source = dict(source_ref='example', revision=1, text=text, sha256=digest(text.encode()))
    material = dict(task=dict(task_id='task', source_ids=['example']), sources=[source],
        candidate=dict(task_id='task', claims=[dict(source_ref='example', revision=1,
            sha256=source['sha256'], start=0, end=len(text.encode()), quote=text, kind='unknown')],
            uncertainty='The source does not establish external truth.', statement='This is always certain.'),
        accepted_result_id='fixture_only', accepted_result_sha256='a' * 64)
    policy = dict(task_id='task:qualified:cold', owning_root_id='root:task', max_compute_units=9,
                  max_model_calls=0, max_children=0, intent_ref='fixture:intent')
    return dict(profile=strategy.PROFILE, source=material,
        history=dict(prior_fp=prior, disposition='USABLE' if prior else 'ABSENT', history_ref='fixture' if prior else None,
            custody_root_id='root:custody', source_scope_sha256=strategy._source_gate(material)['source_scope_sha256']),
        policy=policy, usage=dict(policy=policy, usage=dict(compute_units=1), host_revision=2),
        envelope=dict(valid_from='2026-10-20T00:00:00Z', valid_to='2026-10-20T00:15:00Z'),
        source_context=dict(bsep_packet=dict(packet_id='fixture:bsep')),
        owner_root='root:task', custody_root='root:custody', task_id=policy['task_id'],
        transaction_id='fixture:transaction', evaluation_time=1792454400,
        definitions=dict(consumer='fixture:consumer'))


def consumer_inputs(original):
    budget, allocation = strategy._allocation(original)
    data = dict(material=original, allocation_proof=dict(budget=budget, allocation=allocation),
                previous=strategy._source_gate(original['source']))
    for index, (branch, ordinal) in enumerate(strategy._selected(allocation)):
        data['q' + str(index)] = strategy._check(dict(source=original['source'], branch=branch, ordinal=ordinal))
    return data


class QualifiedStrategyTests(unittest.TestCase):
    def test_qualified_prior_redistributes_actual_finite_inventory(self):
        cold = strategy._consume(consumer_inputs(basis()))
        qualified = strategy._consume(consumer_inputs(basis(-62500000)))
        self.assertEqual(cold['consumed_units'], 7)
        self.assertEqual(qualified['consumed_units'], 7)
        counts = lambda value: {branch: sum(row['branch'] == branch for row in value['consumed_checks'])
                               for branch in strategy.BRANCHES}
        self.assertEqual(counts(cold), {'quotation': 4, 'qualification': 3})
        self.assertEqual(counts(qualified), {'quotation': 3, 'qualification': 4})
        self.assertNotIn('absolute_word_audit', [row['check'] for row in cold['consumed_checks']])
        self.assertIn('absolute_word_audit', [row['check'] for row in qualified['consumed_checks']])
        self.assertIs(qualified['additional_review_required'], True)

    def test_hard_mask_excludes_higher_score_with_same_total(self):
        budget, allocation = strategy._allocation(basis(-62500000))
        excluded = strategy._lid('branch', 'external_unapproved')
        self.assertIn(excluded, [row['id'] for row in allocation['exclusions']])
        self.assertNotIn(excluded, [row['id'] for row in allocation['rows']])
        self.assertEqual(allocation['target'] + allocation['mandatory_units'] + budget['spent'], budget['total'])
        self.assertEqual(budget['total'], 9)
        self.assertTrue(all(branch != 'external_unapproved' for branch, _ in strategy._selected(allocation)))

    def test_consumer_rejects_wrong_selected_work_or_originals(self):
        for mutation in ('count', 'output', 'omitted', 'scope', 'budget'):
            with self.subTest(mutation=mutation):
                data = consumer_inputs(basis(-62500000))
                if mutation == 'count':
                    data['allocation_proof']['allocation']['rows'][0]['allocation'] += 1
                elif mutation == 'output':
                    data['q0']['finding'] = {'fabricated': True}
                elif mutation == 'omitted':
                    del data['q6']
                elif mutation == 'scope':
                    data['material']['history']['source_scope_sha256'] = 'f' * 64
                else:
                    data['allocation_proof']['budget']['total'] += 1
                with self.assertRaises((ValueError, KeyError)):
                    strategy._consume(data)

    def test_expired_prior_cannot_be_relabelled_with_nonzero_value(self):
        original = basis(-62500000)
        original['history']['disposition'] = 'EXPIRED'
        with self.assertRaisesRegex(ValueError, 'qualified_raw_prior'):
            strategy.derive_budget(original)

    def test_no_unsealed_cold_execution(self):
        with self.assertRaisesRegex(ValueError, 'qualified_sealed_current_history_required'):
            strategy.run(None, None)


if __name__ == '__main__':
    unittest.main()
