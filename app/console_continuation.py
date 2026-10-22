"""One explicit console acknowledgement of already closed local occupancy.

No function performs AUTH, network, model, retrieval, cancellation or effects.
Import only after exact source review. The old UNKNOWN row remains immutable.
"""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time

PASSAGE = 'review/stream_console_continuation_passage'
PROPOSAL = PASSAGE + '/continuation_proposal.json'
REVIEW = PASSAGE + '/continuation_review.json'
RUNTIME_REVIEW = PASSAGE + '/runtime_source_review.json'
OWNER_REVIEW = PASSAGE + '/owner_source_review.json'
RECEIPT = 'state/console_continuation_073219.json'
VERSION = 'radik.console_turn_ledger.v03'
LEGACY_VERSION = 'radik.console_turn_ledger.v02'
RECEIPT_VERSION = 'radik.console_local_continuation_receipt.v01'
ATTEMPT_ID = 'radik-call:1548d2e6967447c1a718a99676bf8818'
RESPONSE_ID = 'resp_0c638e609fc87bee016ad1d2f9e49487d29d567b460c366f39'
OLD_OPERATION = '5a6f709e-6b6d-4a6d-a7af-f193f569f19f'
OLD_RUN = '5b18e9f2d957'
OLD_RAW = 'f0c74ab2e07b93c04fa7d7c4e723e362bbccf223a81282c1f6d1b7cfb4228fbf'
OLD_HEAD = '17c3d973808448b9a85b6c4894962574fa1fc9fd10dc6c9201fdc1192660dc55'
BODY_SHA = '434b16d7161bb64a7c2ae0607e74c164631fc66900f3981f6827dacf756bb951'
CONTEXT_SHA = '78e9001b014a5e0096c0ea9b4b953e0d903745a2102adffeaf6eadb2b1db7755'
OLD_SOURCE = 'd7398e45cc8e5da4969c839b95cc282cf9bb4f3fe42495dfa8db7f11c0449cef'
OLD_AUTH = 'dc3b33d4d73ba9c6c12d422bfa24b92d563fb21d516de0d8ba9147f5dc9f4f39'
ACTUAL_LEDGER = PASSAGE + '/actual_evidence/actual_owner/console_model_turns.json'
ACTUAL_RESULT = PASSAGE + '/actual_evidence/actual_transport/result_1548d2e6967447c1a718a99676bf8818.json'
ACTUAL_RESERVED = PASSAGE + '/actual_evidence/actual_transport/reserved_1548d2e6967447c1a718a99676bf8818.json'
OLD_RUNTIME_REVIEW = PASSAGE + '/actual_evidence/reviewed_basis/review/stage04_prelive_passage/runtime_source_review.json'
OLD_OWNER_REVIEW = PASSAGE + '/actual_evidence/reviewed_basis/review/stage04_prelive_passage/owner_source_review.json'
RECEIPT_FIELDS = frozenset({'schema', 'disposition', 'attempt_id', 'response_id',
    'old_ledger_raw_sha256', 'old_ledger_canonical_sha256', 'historical_prefix_sha256',
    'context_sha256', 'body_sha256', 'local_http_closed', 'local_watchdog_finished',
    'remote_outcome', 'usage', 'automatic_retry', 'server_cancellation_observed',
    'source_identity_sha256', 'auth_source_identity_sha256', 'review_ref',
    'owner_operation_id', 'run_id', 'recorded_at', 'receipt_sha256'})
ACTUAL_PINS = {'review/stream_console_continuation_passage/actual_evidence/actual_owner/connected_result.json': '1d1a2d7b8418380158a05826f96b3588ff03e28a3c02405942f2d0f8740b74dd', 'review/stream_console_continuation_passage/actual_evidence/actual_owner/console_budget_activation.json': '0b6c1f83a9e92c2eaeffa73cee9d90757d9ec701fb69fb72b4ecae0d77ad0cdd', 'review/stream_console_continuation_passage/actual_evidence/actual_owner/console_model_turns.json': 'f0c74ab2e07b93c04fa7d7c4e723e362bbccf223a81282c1f6d1b7cfb4228fbf', 'review/stream_console_continuation_passage/actual_evidence/actual_owner/console_stage04_committed.json': 'b7768e0e144cdca717bcd623eca18761097a3d91309a7926fd96e0c02f2e19f3', 'review/stream_console_continuation_passage/actual_evidence/actual_owner/console_stage04_transition.json': '1af1aac09309f216159455fda96dd28a705a2df9c0c10db37c4d3ac56ac82979', 'review/stream_console_continuation_passage/actual_evidence/actual_owner/exam_ledger.json': '70285a6ad3a63cdd6e211ac9749bc84ece1d81efd47983ea5071d9f596a5e7bd', 'review/stream_console_continuation_passage/actual_evidence/actual_owner/owner_auth_observations.json': 'fccd0e2b5fa776c6670647adc2fe60113badb5716021dd9194a6e9c850e7bdba', 'review/stream_console_continuation_passage/actual_evidence/actual_owner/owner_dependency_observation.json': 'e7dc11e48e929cf86a68eab1c274bcda2de54d7bcb719efa5c3be665365e7e28', 'review/stream_console_continuation_passage/actual_evidence/actual_owner/owner_phase_journal.json': '4b46152d04ded9ad3de15dde7e1c45f2210ec961625d0bed5bc5d9705978267d', 'review/stream_console_continuation_passage/actual_evidence/actual_owner/owner_state.json': 'c82aff2dbb008c0b6ba3d8fce19c23dfce6ee6875cbf865fc5f7855bba01dd68', 'review/stream_console_continuation_passage/actual_evidence/actual_owner/task_model_settings.json': '706c4c4bd70359227703a9617e522fcaf882c066cb7fa639572cf54b4a98d054', 'review/stream_console_continuation_passage/actual_evidence/actual_sources/3c02aa364044a8c18a855990acf99770.txt': '36d9fd6ff7564b9464603151edb0e77be22ed8d14723dc50b552b5c2a0874a81', 'review/stream_console_continuation_passage/actual_evidence/actual_sources/bdd0db29862cdf1b8cf0e8d0e488add8.txt': '38020aa2c4bf36a82fd2862d4db3292fb40e203183ca9673123a05e7e441727e', 'review/stream_console_continuation_passage/actual_evidence/actual_sources/f13e2cc60156292aa2c6855d26548099.txt': '2d98ea23003f3782ad0fa8968f7cf8c3568bca819dbd699f1e2a632f126db35d', 'review/stream_console_continuation_passage/actual_evidence/actual_task_state/dynamic_source_revisions.json': '2950ecb4cf250a0f96b203513a3e5e155739fda493ddf1e2b45f2f941a1862a5', 'review/stream_console_continuation_passage/actual_evidence/actual_task_state/dynamic_tasks.json': '0a25e66823e1fcf4477fbdbbac50d85252d5e72a35c5b5c28bdd3cb392b31a71', 'review/stream_console_continuation_passage/actual_evidence/actual_task_state/owned_effect_policy.json': '8c168be984a6b8ab7463a2d6ec9a004ab14be3475cc92b0180c7d81ec4a540e9', 'review/stream_console_continuation_passage/actual_evidence/actual_transport/catalog_f0dd8d3b35724a208b13d56f01a6636c.json': 'ada55e97d216dc6a399ecc15e30e5d225d227b910731e40bd09f484acae09a28', 'review/stream_console_continuation_passage/actual_evidence/actual_transport/catalog_http_fa955670da1b4bd28c16481c27094fed.json': 'cbaa52475d0a41dec8a9b36eebf9467e6577afae31cd27a54d7fe0c0a81a01dc', 'review/stream_console_continuation_passage/actual_evidence/actual_transport/http_1548d2e6967447c1a718a99676bf8818.json': '38ad1e1ffa96107c99049b622f7d2e636b813bee908852134b3f935746955956', 'review/stream_console_continuation_passage/actual_evidence/actual_transport/reserved_1548d2e6967447c1a718a99676bf8818.json': '297b1e60951671c64e365610617c7b4216645de87fd69847f48d4dc15db4b19b', 'review/stream_console_continuation_passage/actual_evidence/actual_transport/result_1548d2e6967447c1a718a99676bf8818.json': 'ea18d4b97803a7e0892354f36d35b8f915302aac46af17bccfd04573f77f3da8', 'review/stream_console_continuation_passage/actual_evidence/actual_witnesses/workspace/owner_documents/review/task_evidence/99658782a3132f197773694bc90e8792b70b5ddb4bd9e338a2061eb719e956f4/dynamic_intake_root_b0e92a2b0743d9bac363fe802065c4c087af0610eba94969e42a11422353b6f7.json': 'b0e92a2b0743d9bac363fe802065c4c087af0610eba94969e42a11422353b6f7', 'review/stream_console_continuation_passage/actual_evidence/reviewed_basis/review/stage04_prelive_passage/console_source_review.json': 'ef7d276f9361090b9910efc21c0b68457896ce113a480402aea2899e3bd95ae1', 'review/stream_console_continuation_passage/actual_evidence/reviewed_basis/review/stage04_prelive_passage/current_source_admission.json': 'bb29dbc61244c30f75546f3f82003da66ca05be8ff921eafb17aed2770802d4a', 'review/stream_console_continuation_passage/actual_evidence/reviewed_basis/review/stage04_prelive_passage/failure_reporter_review.json': '3c28af98b42e84a16c16e9ad92b5d1068f3caec1f998d8119b17adb82328b0fa', 'review/stream_console_continuation_passage/actual_evidence/reviewed_basis/review/stage04_prelive_passage/mechanical_result_review.json': 'a70724fbc41d3651eb54d81628e8eea2813516389c79a4a274aced6fef4a801a', 'review/stream_console_continuation_passage/actual_evidence/reviewed_basis/review/stage04_prelive_passage/owner_source_review.json': 'a26e22dd3bfee2ecfe0a2fa2164ce20dbf6c37c48ff2ea927a69facafe5d71aa', 'review/stream_console_continuation_passage/actual_evidence/reviewed_basis/review/stage04_prelive_passage/real_execution_review.json': '4a8247a27c05008841ca49b1d4905d640a56ee7d5977699613555e675ea9a5dc', 'review/stream_console_continuation_passage/actual_evidence/reviewed_basis/review/stage04_prelive_passage/runtime_source_review.json': 'ec51d50535c8e0ad7b2d03d728aa2a4e105d55884bc4cec3a486064771949dc5', 'review/stream_console_continuation_passage/actual_evidence/writer_basis/app/stage04_diagnostics.py': 'a1e612a06392d545d482e71919a6dd7e633444faa421d3a84ac51ba5e251d7cd', 'review/stream_console_continuation_passage/actual_evidence/writer_basis/review/package_direct_plan_return.py': '576f408731ede2ddd910b1f979dad06b7cab43d88fee9a47d6d38c46968ef9c5', 'review/stream_console_continuation_passage/actual_evidence/writer_basis/review/transport/owner_failure_report.py': 'e67f33324e2ecc837e4e148c8d124e645bf6af567756e4b88dce7f5203e91bf9'}
HISTORICAL_SOURCE_FILES = {'app/__init__.py': {'path': 'review/stream_console_continuation_passage/before/app/__init__.py', 'sha256': '82c5060447b21d1a62b62d82e98655ffdc4963c700eca249a758a6b6c9b68e76'}, 'app/budget.py': {'path': 'review/stream_console_continuation_passage/before/app/budget.py', 'sha256': 'ab050a4462cfe77f4b45f163ca65c2a8953c02dc8784ad47ed119f2a7f3ae6d8'}, 'app/contracts.py': {'path': 'review/stream_console_continuation_passage/before/app/contracts.py', 'sha256': '7c4d3ec9f4762fe01bebcc398b728a674afe8084e585b59f884e7c1b1906c33b'}, 'app/controller.py': {'path': 'review/stream_console_continuation_passage/before/app/controller.py', 'sha256': '5bc1009b215b2989d13b4ec115fa407edadd103be10314374eeb663cdebddf51'}, 'app/dynamic_control.py': {'path': 'review/stream_console_continuation_passage/before/app/dynamic_control.py', 'sha256': '32e1b99639a3d1424cadd446a01f1a1bb65a508ef541a34233a3f31e1eb4cc9c'}, 'app/dynamic_native.py': {'path': 'review/stream_console_continuation_passage/before/app/dynamic_native.py', 'sha256': '7d6f5c31ea593d1553723e47251ead5a18492cbcea077228339604c287d9e58b'}, 'app/dynamic_roles.py': {'path': 'review/stream_console_continuation_passage/before/app/dynamic_roles.py', 'sha256': 'b151f3b6fe044219fad8e7ae045e568aa402a56b0723dd2470119de63573838f'}, 'app/dynamic_semantics.py': {'path': 'review/stream_console_continuation_passage/before/app/dynamic_semantics.py', 'sha256': 'ec2e206f4361e2009ba9e996751e1ad470bd447c4f975b92ad26377fd47438ed'}, 'app/dynamic_temporal.py': {'path': 'review/stream_console_continuation_passage/before/app/dynamic_temporal.py', 'sha256': 'c4e76baf9aced7e8393dde30134a79d45ea2b3f00801b7b4ed732cb4de046cac'}, 'app/dynamic_work.py': {'path': 'review/stream_console_continuation_passage/before/app/dynamic_work.py', 'sha256': '035e90b19f5fea5683123518fa934158d30e41b38f186e8a105948d037879543'}, 'app/evidence.py': {'path': 'review/stream_console_continuation_passage/before/app/evidence.py', 'sha256': 'f4a5b87bdc48d107e8abc9a85d7308f93566ba07604d3aa7e0e02bf034266410'}, 'app/intake.py': {'path': 'review/stream_console_continuation_passage/before/app/intake.py', 'sha256': 'a4726a6ef6ef6a4e70f9b984662fee8d0e91d4dac1ecf0038804f5df86e86b74'}, 'app/memory.py': {'path': 'review/stream_console_continuation_passage/before/app/memory.py', 'sha256': '163126dcb8f1eb39845bb04427b60df85dc2b21941d4d0ae3ad68552582ccf43'}, 'app/native_authority.py': {'path': 'review/stream_console_continuation_passage/before/app/native_authority.py', 'sha256': '701cd41e60b63209270b509669b24cba9f002cc8796e2c5bfa8a6228bd678639'}, 'app/native_document.py': {'path': 'review/stream_console_continuation_passage/before/app/native_document.py', 'sha256': 'b2de73f3b468043308cce8ff99c8730495baa54aa5c29ccc576cfacac1ae2bb8'}, 'app/openai_plan_transport.py': {'path': 'review/stream_console_continuation_passage/before/app/openai_plan_transport.py', 'sha256': '9a5edef555482f4699202dc6f29e864326e2de3ff372fc7c308c568eab2042e1'}, 'app/plan_auth.py': {'path': 'review/stream_console_continuation_passage/before/app/plan_auth.py', 'sha256': 'ac183f3493eb6411e35c93bac30de7c69bd9d3d8d72f026cecc1716e7e963687'}, 'app/proposal.py': {'path': 'review/stream_console_continuation_passage/before/app/proposal.py', 'sha256': '07f50480f658f7679a8204d54e1531fc6d649f8674493f9ca913704b1f5f8b1f'}, 'app/runtime.py': {'path': 'review/stream_console_continuation_passage/before/app/runtime.py', 'sha256': '3601eabf972088bef01527dd3dbe4267920937e865bab8b9e4c0489a4e97c3d3'}, 'app/save_quota.py': {'path': 'review/stream_console_continuation_passage/before/app/save_quota.py', 'sha256': 'a65b3185936688823360694e26e34f2463938ea00492f058e51a1792c98fd901'}, 'app/semantic_membrane.py': {'path': 'review/stream_console_continuation_passage/before/app/semantic_membrane.py', 'sha256': '4c584fcd6021dba6401230412977925c494bf56b03d12fb423e43a34d1a64c99'}, 'app/source_admission.py': {'path': 'review/stream_console_continuation_passage/before/app/source_admission.py', 'sha256': '8e03615ac1b9fa575898cb2298ab12ae164aac4bc969831da349f8f8dca0a2e4'}, 'app/stage04_diagnostics.py': {'path': 'review/stream_console_continuation_passage/before/app/stage04_diagnostics.py', 'sha256': 'a1e612a06392d545d482e71919a6dd7e633444faa421d3a84ac51ba5e251d7cd'}, 'app/task_budget.py': {'path': 'review/stream_console_continuation_passage/before/app/task_budget.py', 'sha256': 'b20b7359ee3e6f2a6c9339aca210cf765651e0c6ce477f6614f75df428326c96'}, 'app/task_spec.py': {'path': 'review/stream_console_continuation_passage/before/app/task_spec.py', 'sha256': 'fcf9b56e79f2178e67baf102b93104b360de0ba868d8b64dd2bb65f910844f53'}, 'app/task_store.py': {'path': 'review/stream_console_continuation_passage/before/app/task_store.py', 'sha256': 'aa580b18fe95cd84c6d5fb58c05b273423c52263641918c768256b593ace76e3'}, 'config/console_model_policy.json': {'path': 'review/stream_console_continuation_passage/before/config/console_model_policy.json', 'sha256': 'ca76784381e49627a85db0027a3c211d87c417f30a59838eb65ca307257e2e31'}, 'config/launch.py': {'path': 'review/stream_console_continuation_passage/before/config/launch.py', 'sha256': '46a80f4f0d0885c5a9faa24d50e3fdbd5b0290eb049e6b88599aa547999335ae'}, 'config/model_policy.json': {'path': 'review/stream_console_continuation_passage/before/config/model_policy.json', 'sha256': 'b9587a72dfd9e74bc3735ec6f8eed79ccf38aaaf0b786bde6eb2570e2d920ca7'}, 'config/requirements-plan-auth.txt': {'path': 'review/stream_console_continuation_passage/before/config/requirements-plan-auth.txt', 'sha256': 'ec54f0f0c92ca38c765d549cf18ff66290ab1c97126a2028657928c14b34af31'}, 'config/requirements-plan-base.txt': {'path': 'review/stream_console_continuation_passage/before/config/requirements-plan-base.txt', 'sha256': 'ed980ab39e698253b5c38d488a81ec5d9a046d6d1ef5ae1896c9bd9eaf3d9e97'}, 'config/task_model_policy.json': {'path': 'review/stream_console_continuation_passage/before/config/task_model_policy.json', 'sha256': '996fcbdfa1770b4b4d8758e281c6c71ff07e32d8c630ac7f428c653082937e53'}, 'radik': {'path': 'review/stream_console_continuation_passage/before/radik', 'sha256': '00508a5aaeb4bb9a8d96ff429f61eaca1d7c3d480baf854cc30aab455df8b514'}, 'review/dependencies/inventory.json': {'path': 'review/stream_console_continuation_passage/before/review/dependencies/inventory.json', 'sha256': 'e69324b7b44341fc001518bfaa96d9c0d7fe2e3228eb8c3730e9e336400fe557'}, 'review/direct_plan_passage/auth_dependency_metadata.json': {'path': 'review/stream_console_continuation_passage/before/review/direct_plan_passage/auth_dependency_metadata.json', 'sha256': '634e7675f6568e4763a3dea92ca1e14b69c1ca34002e072749acde644790f123'}, 'review/direct_plan_passage/bootstrap_identity.json': {'path': 'review/stream_console_continuation_passage/before/review/direct_plan_passage/bootstrap_identity.json', 'sha256': 'e8a24d947ca3a1a4cc69784fd5864b725ebe6c31f94102a3a76eb208e2124eea'}, 'review/direct_plan_passage/protocol_references.json': {'path': 'review/stream_console_continuation_passage/before/review/direct_plan_passage/protocol_references.json', 'sha256': '5a57122af814c5e37b60d0f3eb8fb2bb208847741d179b305f8ab07c483a7da6'}, 'review/live_exam_document.py': {'path': 'review/stream_console_continuation_passage/before/review/live_exam_document.py', 'sha256': 'f1c5bb3ca75a7c9004fd53db130df018baa88a56beb2100cf14a0a22c65c1642'}, 'review/package_direct_plan_return.py': {'path': 'review/stream_console_continuation_passage/before/review/package_direct_plan_return.py', 'sha256': '576f408731ede2ddd910b1f979dad06b7cab43d88fee9a47d6d38c46968ef9c5'}, 'review/transport/direct_plan_gate.py': {'path': 'review/stream_console_continuation_passage/before/review/transport/direct_plan_gate.py', 'sha256': 'f19ad0d7b4771b411b2bb4b7e224876b0dccbc512727331f505e4687e72efaf6'}, 'review/transport/model_scope.py': {'path': 'review/stream_console_continuation_passage/before/review/transport/model_scope.py', 'sha256': '27f538d8cdca68ae2c2efb517f7520f53c3d94a76079b5c7ecf5d19d8798008b'}, 'review/transport/owner_failure_report.py': {'path': 'review/stream_console_continuation_passage/before/review/transport/owner_failure_report.py', 'sha256': 'e67f33324e2ecc837e4e148c8d124e645bf6af567756e4b88dce7f5203e91bf9'}, 'review/transport/plan_dependencies.py': {'path': 'review/stream_console_continuation_passage/before/review/transport/plan_dependencies.py', 'sha256': '740eda10b97c2e080e5b967c623bba54e3e6b8770aba9b559175aedf2ead3caa'}, 'review/transport/radik_owner_start.py': {'path': 'review/stream_console_continuation_passage/before/review/transport/radik_owner_start.py', 'sha256': '24422dc24e96638094493d1065c823551aa1d1926b0586ae855b136e6d2c0999'}, 'source/reference/docs/common_action_and_dynamic_composition_checkpoint_v01.md': {'path': 'source/reference/docs/common_action_and_dynamic_composition_checkpoint_v01.md', 'sha256': 'fd708a885e0635e9f82bb8baad212f9cbd6db363888a8ae380893a718201e5e9'}, 'source/reference/docs/common_action_and_dynamic_composition_contract_v01.md': {'path': 'source/reference/docs/common_action_and_dynamic_composition_contract_v01.md', 'sha256': '7f747d14065c11e6194fce94aabcd107693e7d27cd75c5558c37cef0a0a3092d'}, 'source/reference/hedgehog/__init__.py': {'path': 'source/reference/hedgehog/__init__.py', 'sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'}, 'source/reference/hedgehog/action_commit_packet_v02.py': {'path': 'source/reference/hedgehog/action_commit_packet_v02.py', 'sha256': 'e24b8c4bd3284c4b9db8944e2a9c268d26816956880ffb0700700bbf3fdc59ac'}, 'source/reference/hedgehog/avf_v02.py': {'path': 'source/reference/hedgehog/avf_v02.py', 'sha256': 'ba88a22b3ddea715ad7af2731c171511273b6e7bb4c67f5d54024464a1a8b616'}, 'source/reference/hedgehog/capability_admission_v01.py': {'path': 'source/reference/hedgehog/capability_admission_v01.py', 'sha256': '2261347c11f7535522653f0a2e301bed69cbbc5e0ef737bc4a37d2b9954b0cda'}, 'source/reference/hedgehog/context_packets.py': {'path': 'source/reference/hedgehog/context_packets.py', 'sha256': '080c69dfe24206549fbf27ae65141105c6e4b4c802b05296f1d90026823e9f32'}, 'source/reference/hedgehog/domains/__init__.py': {'path': 'source/reference/hedgehog/domains/__init__.py', 'sha256': 'f33ec43826cba0521f58774c1500cb6f84d72bb36d88db8d41c7f1992cdb80a8'}, 'source/reference/hedgehog/domains/airline/__init__.py': {'path': 'source/reference/hedgehog/domains/airline/__init__.py', 'sha256': 'cc46b98e70deb6ea9b8eb5ea184cda638ce7365a1870e5074d2dfc837dab9cf8'}, 'source/reference/hedgehog/domains/airline/outcome_feedback_adapter_v01.py': {'path': 'source/reference/hedgehog/domains/airline/outcome_feedback_adapter_v01.py', 'sha256': 'fda3fa3dd7ffc5fbbe87ed7e424699d765e1a37058c805cff19761b984734575'}, 'source/reference/hedgehog/domains/airline/semantic_to_contract_binding_v01.py': {'path': 'source/reference/hedgehog/domains/airline/semantic_to_contract_binding_v01.py', 'sha256': '6b9f34433cae8ef0435ea1456820fd4f7e300a2a6c9a2d389c77c3db008be4a6'}, 'source/reference/hedgehog/domains/airline/semantic_to_contract_causal_runtime_v01.py': {'path': 'source/reference/hedgehog/domains/airline/semantic_to_contract_causal_runtime_v01.py', 'sha256': '3693ae3d5b15d16bfa23f7d3ebf40bb64a0aa9f245847a1d0d09eae431458e98'}, 'source/reference/hedgehog/domains/airline/ticket_purchase_corridor_runtime_v01.py': {'path': 'source/reference/hedgehog/domains/airline/ticket_purchase_corridor_runtime_v01.py', 'sha256': '0e9864fb499f378edeeb8300b785a8de69af2fbcb51ad4039d9306e182adb0eb'}, 'source/reference/hedgehog/domains/airline/ticket_purchase_corridor_v01.py': {'path': 'source/reference/hedgehog/domains/airline/ticket_purchase_corridor_v01.py', 'sha256': '5bf787130b370da4c58918ef4a65de29aa7c017a59d9fc491ad5c4ee66a50e3b'}, 'source/reference/hedgehog/domains/airline/transaction_artifact_ledger_collector_v01.py': {'path': 'source/reference/hedgehog/domains/airline/transaction_artifact_ledger_collector_v01.py', 'sha256': 'af7dc4da6ce1185688447d96747516a521084ec7c749c8490ea92f3ee65264c4'}, 'source/reference/hedgehog/domains/airline/transaction_artifact_ledger_v01.py': {'path': 'source/reference/hedgehog/domains/airline/transaction_artifact_ledger_v01.py', 'sha256': '3e9cdcd6d3c411b4dfab598d4b62b5648dcf071d4bf15e8297e3d4144aa831bf'}, 'source/reference/hedgehog/domains/ephemeral_workspace/__init__.py': {'path': 'source/reference/hedgehog/domains/ephemeral_workspace/__init__.py', 'sha256': 'f1eba5acd64fe400ab325106031e2d90f963ddb2df0e33f43eb4cc0d95b00e1f'}, 'source/reference/hedgehog/domains/ephemeral_workspace/capability_registry_v01.py': {'path': 'source/reference/hedgehog/domains/ephemeral_workspace/capability_registry_v01.py', 'sha256': 'c76070da03489e0e9ec8c3784f61520ef2866ebd7a5eaf6d9470e369500e11a3'}, 'source/reference/hedgehog/domains/ephemeral_workspace/contracts_v01.py': {'path': 'source/reference/hedgehog/domains/ephemeral_workspace/contracts_v01.py', 'sha256': '9e2a69ed5c02ae9c8febfe2d3064a967598e21c61d80eecd84fd08efad093c9b'}, 'source/reference/hedgehog/domains/ephemeral_workspace/evidence_v01.py': {'path': 'source/reference/hedgehog/domains/ephemeral_workspace/evidence_v01.py', 'sha256': '792736b91f2a3fa264613fa6bc1bea60e4370fd8ba7f56c427fc0323f39ca1c7'}, 'source/reference/hedgehog/domains/ephemeral_workspace/kernel_adapter_v01.py': {'path': 'source/reference/hedgehog/domains/ephemeral_workspace/kernel_adapter_v01.py', 'sha256': '15f1243f5dd0d1d798267c48359622983b99387f5b15df2b081620b7516ae1ee'}, 'source/reference/hedgehog/domains/ephemeral_workspace/local_services_v01.py': {'path': 'source/reference/hedgehog/domains/ephemeral_workspace/local_services_v01.py', 'sha256': '1abe5cd160a9ae7475334f2b396057366ab4a7c477a7ea62288c702018f1c1a3'}, 'source/reference/hedgehog/domains/ephemeral_workspace/media_continuation_v01.py': {'path': 'source/reference/hedgehog/domains/ephemeral_workspace/media_continuation_v01.py', 'sha256': '8728b7a47740736bb3d7145acb874fa1e545614e4adf3d1dd94e4230ea4d0210'}, 'source/reference/hedgehog/domains/ephemeral_workspace/media_v01.py': {'path': 'source/reference/hedgehog/domains/ephemeral_workspace/media_v01.py', 'sha256': '87e2388ceab077e330c144cf3d730341e5a44fdc51131d7aa0969ad490b6d7fa'}, 'source/reference/hedgehog/domains/ephemeral_workspace/memory_adapter_v01.py': {'path': 'source/reference/hedgehog/domains/ephemeral_workspace/memory_adapter_v01.py', 'sha256': 'ce4944c25a03ac4ca0d2d2c3eb1b3c68ac0d5f2dd012a31a7705642b4a3ba569'}, 'source/reference/hedgehog/domains/ephemeral_workspace/outcome_feedback_adapter_v01.py': {'path': 'source/reference/hedgehog/domains/ephemeral_workspace/outcome_feedback_adapter_v01.py', 'sha256': 'a46a0e422a36d65673df229116d2137c14efd7cf7c90552c703b55ec00e77099'}, 'source/reference/hedgehog/domains/ephemeral_workspace/semantic_adapter_v01.py': {'path': 'source/reference/hedgehog/domains/ephemeral_workspace/semantic_adapter_v01.py', 'sha256': 'ef42d7529134d9c7f9908dac0ddb08a62d1d9d2a838b1baf38c58316b468dfce'}, 'source/reference/hedgehog/domains/ephemeral_workspace/semantic_roles_v01.py': {'path': 'source/reference/hedgehog/domains/ephemeral_workspace/semantic_roles_v01.py', 'sha256': '1d1e8162df04f300143659022d067941413918bd6afe9702b7a08f701a9eb56d'}, 'source/reference/hedgehog/domains/ephemeral_workspace/session_runtime_v01.py': {'path': 'source/reference/hedgehog/domains/ephemeral_workspace/session_runtime_v01.py', 'sha256': 'd3841d5f6faa4dd9e8c9db6373658366d1cc89ae54b0826351de64095276c5cc'}, 'source/reference/hedgehog/domains/landslide_sentinel/__init__.py': {'path': 'source/reference/hedgehog/domains/landslide_sentinel/__init__.py', 'sha256': '3cbfd0a8d204091544a848ae417615837dec904f3d48135126a4eef53457f9b5'}, 'source/reference/hedgehog/domains/landslide_sentinel/capability_registry_v01.py': {'path': 'source/reference/hedgehog/domains/landslide_sentinel/capability_registry_v01.py', 'sha256': '2542479dddc7485cb1e2220fac51dd59849d571054c1c912b3be3dbd58b0dd28'}, 'source/reference/hedgehog/domains/landslide_sentinel/contracts_v01.py': {'path': 'source/reference/hedgehog/domains/landslide_sentinel/contracts_v01.py', 'sha256': 'bd6bb60cee50a5ef3bdc9d2a79216a3f4c0685fe09cd5dc2837623cb166aa226'}, 'source/reference/hedgehog/domains/landslide_sentinel/events_v01.py': {'path': 'source/reference/hedgehog/domains/landslide_sentinel/events_v01.py', 'sha256': 'e1502016a2ddf63b0464dd72ee52a5caefa666327f50036c3c84d045ed9e18be'}, 'source/reference/hedgehog/domains/landslide_sentinel/evidence_v01.py': {'path': 'source/reference/hedgehog/domains/landslide_sentinel/evidence_v01.py', 'sha256': '0f015f1d876afde74aa9323c49c682f54b8c3042b2e38886235e860e7a170b27'}, 'source/reference/hedgehog/domains/landslide_sentinel/incident_policy_v01.py': {'path': 'source/reference/hedgehog/domains/landslide_sentinel/incident_policy_v01.py', 'sha256': '9ea35362d3f3c7341dc05d4db0a4a5c3bc089bb63512e85d5018c8ea5e290947'}, 'source/reference/hedgehog/domains/landslide_sentinel/kernel_adapter_v01.py': {'path': 'source/reference/hedgehog/domains/landslide_sentinel/kernel_adapter_v01.py', 'sha256': '9f9c63e8edb6ae441e30275ae5b9131c711b71648b650d22606aae818ac22521'}, 'source/reference/hedgehog/domains/landslide_sentinel/monitoring_runtime_v01.py': {'path': 'source/reference/hedgehog/domains/landslide_sentinel/monitoring_runtime_v01.py', 'sha256': '5c1f36976661ae83b49086aad35652761bd550aab51cd8a4e1287af5d6e04003'}, 'source/reference/hedgehog/domains/landslide_sentinel/outbox_v01.py': {'path': 'source/reference/hedgehog/domains/landslide_sentinel/outbox_v01.py', 'sha256': 'c6ed19e959908400e76942aa8e5e20c02c0b4fb662655576025188ae49860f2e'}, 'source/reference/hedgehog/domains/landslide_sentinel/outcome_feedback_adapter_v01.py': {'path': 'source/reference/hedgehog/domains/landslide_sentinel/outcome_feedback_adapter_v01.py', 'sha256': '886199bd3ca337463027490fa8d126bc08af12e2144b9d57d52d4f11449ca8b4'}, 'source/reference/hedgehog/domains/landslide_sentinel/semantic_adapter_v01.py': {'path': 'source/reference/hedgehog/domains/landslide_sentinel/semantic_adapter_v01.py', 'sha256': '6fac1601e171b56548bdc49c5c9a197a9c2305d1e3bddf1c12404d00830ae8aa'}, 'source/reference/hedgehog/domains/supplier_water_filter/__init__.py': {'path': 'source/reference/hedgehog/domains/supplier_water_filter/__init__.py', 'sha256': 'dbca71e4fe22c58cd4b24f46f069c5e2e9fe60c30503dc7489a1f162bb818fa0'}, 'source/reference/hedgehog/domains/supplier_water_filter/adversarial_feedback_v01.py': {'path': 'source/reference/hedgehog/domains/supplier_water_filter/adversarial_feedback_v01.py', 'sha256': '683260a8c524f451c061e6da5207fa1196f41b1a0398167c15fa7a1b9c3b8bc6'}, 'source/reference/hedgehog/domains/supplier_water_filter/gate3_runtime_v01.py': {'path': 'source/reference/hedgehog/domains/supplier_water_filter/gate3_runtime_v01.py', 'sha256': '4ce5ccbbbe8c0235533885326c9dc1cf092201ddff228fe8e0bcc80d5eca87bc'}, 'source/reference/hedgehog/domains/supplier_water_filter/kernel_adapter_v01.py': {'path': 'source/reference/hedgehog/domains/supplier_water_filter/kernel_adapter_v01.py', 'sha256': '0ec36f709977b85f457739e1266ba3889a5735eee2dc89f033a34e45512abdfe'}, 'source/reference/hedgehog/domains/supplier_water_filter/outcome_feedback_adapter_v01.py': {'path': 'source/reference/hedgehog/domains/supplier_water_filter/outcome_feedback_adapter_v01.py', 'sha256': 'e64d0e5b20eb576b8edfe60ff25ab8ee720011b9da61a69d2bb117a246f1aca2'}, 'source/reference/hedgehog/domains/testflix/__init__.py': {'path': 'source/reference/hedgehog/domains/testflix/__init__.py', 'sha256': '65d25f90889210a6de7ee1d89290e5f3fed0672cd40139287c08b807030c4acf'}, 'source/reference/hedgehog/domains/testflix/contracts_v01.py': {'path': 'source/reference/hedgehog/domains/testflix/contracts_v01.py', 'sha256': 'cafe20c56049985bf4031104343f9f068d1e3fe989fbf8c132f47adb2826ef0b'}, 'source/reference/hedgehog/domains/testflix/evidence_v01.py': {'path': 'source/reference/hedgehog/domains/testflix/evidence_v01.py', 'sha256': '3106f3e3459a4585385f170579f4a166f3aad4e330502711394a8be947d589ae'}, 'source/reference/hedgehog/domains/testflix/kernel_adapter_v01.py': {'path': 'source/reference/hedgehog/domains/testflix/kernel_adapter_v01.py', 'sha256': '1444d89f426658949cc0b0c2fae234943cef4454777981a89cff444327412eae'}, 'source/reference/hedgehog/domains/testflix/lifecycle_v01.py': {'path': 'source/reference/hedgehog/domains/testflix/lifecycle_v01.py', 'sha256': '9acf70b4a811c9ec34f7b4e7a580bee6fe25001f39bb2c3042e87378bb72cb2b'}, 'source/reference/hedgehog/domains/testflix/live_semantic_adapter_v01.py': {'path': 'source/reference/hedgehog/domains/testflix/live_semantic_adapter_v01.py', 'sha256': '6a1b6d8286a986dc4459c2ea5dea999e0ed49e3784cc253c4ca05a5405b45bec'}, 'source/reference/hedgehog/domains/testflix/mock_world_v01.py': {'path': 'source/reference/hedgehog/domains/testflix/mock_world_v01.py', 'sha256': '929d9d64f87551ae53e598075a11f175b42c7a8b4daf47ab95af103233b6ab32'}, 'source/reference/hedgehog/domains/testflix/outcome_feedback_adapter_v01.py': {'path': 'source/reference/hedgehog/domains/testflix/outcome_feedback_adapter_v01.py', 'sha256': 'c979f15b8dc093a9924060efc5db05917ccf20c86d55b1a50b738ac4fa25bde6'}, 'source/reference/hedgehog/domains/testflix/semantic_adapter_v01.py': {'path': 'source/reference/hedgehog/domains/testflix/semantic_adapter_v01.py', 'sha256': 'a20b22edbf26e536c3403d9dabe05fd22ea82cbe0210bb87eaada25f47b5c7e5'}, 'source/reference/hedgehog/domains/testflix/semantic_roles_v01.py': {'path': 'source/reference/hedgehog/domains/testflix/semantic_roles_v01.py', 'sha256': '7855b9d9011307cd79512fec2c10672b96b5d71dccd09b87a5cf88314dccc736'}, 'source/reference/hedgehog/drs.py': {'path': 'source/reference/hedgehog/drs.py', 'sha256': '7e78be61a24f285608841cbd8d07047967fb0abf7708173eadeff5f5578553f4'}, 'source/reference/hedgehog/drs_g2b_compatibility_v01.py': {'path': 'source/reference/hedgehog/drs_g2b_compatibility_v01.py', 'sha256': '5d4fb04cbf2e0819a0df5da17df724a0441747d2573fff924086dc9cfabaece1'}, 'source/reference/hedgehog/drs_memory_resolution_v01.py': {'path': 'source/reference/hedgehog/drs_memory_resolution_v01.py', 'sha256': '698a34262d4442dba1474a1a137ca19057c27d2d20595a9f82e848c3816579d8'}, 'source/reference/hedgehog/drs_semantic_address_v01.py': {'path': 'source/reference/hedgehog/drs_semantic_address_v01.py', 'sha256': '9b0cae8c7d5f02cec8d3df573d7107b7b4b013b3e7416480e871b833aa6e2e20'}, 'source/reference/hedgehog/evidence/__init__.py': {'path': 'source/reference/hedgehog/evidence/__init__.py', 'sha256': '2fa905efbd7f2a968d8a648ef14ef676a4f64bac94a159651c7a4d7b71a81b8b'}, 'source/reference/hedgehog/evidence/external_anchor_v01.py': {'path': 'source/reference/hedgehog/evidence/external_anchor_v01.py', 'sha256': '299c6d2daabfe53c0c93c76a46709d09c4cc26b89907af17a30dab8ce8537994'}, 'source/reference/hedgehog/evidence/sealed_evidence_profile_v01.py': {'path': 'source/reference/hedgehog/evidence/sealed_evidence_profile_v01.py', 'sha256': '3845a246e641aea8da3d9314e2d140bcb701a5488cb9de8153a62f0d84529b37'}, 'source/reference/hedgehog/evidence/sealed_package_v01.py': {'path': 'source/reference/hedgehog/evidence/sealed_package_v01.py', 'sha256': '4fecf1b24696316348256acd1bd5a9e7a237dc37bd5b11abc41a71257796af53'}, 'source/reference/hedgehog/evidence/sealed_replay_evidence_v01.py': {'path': 'source/reference/hedgehog/evidence/sealed_replay_evidence_v01.py', 'sha256': 'f40e48f3d32f4b67250534f5d47d5bb4e076890497506ec4315d9ce06261c5a3'}, 'source/reference/hedgehog/gate3_mechanism_v01.py': {'path': 'source/reference/hedgehog/gate3_mechanism_v01.py', 'sha256': 'ef6bb77e245aea411cd0f400496a25c9f1002007b8021c15232b3229ffc856f8'}, 'source/reference/hedgehog/gt_validator.py': {'path': 'source/reference/hedgehog/gt_validator.py', 'sha256': 'e8fa9af23cbff04a059523aa25e47eec790c00776c902e545f1779e20ee5f0dd'}, 'source/reference/hedgehog/kernel/__init__.py': {'path': 'source/reference/hedgehog/kernel/__init__.py', 'sha256': 'b26dad7e3a5d47b2d717f002a0982bd0bb0fcde95110627846d81d747a0e4be1'}, 'source/reference/hedgehog/kernel/abi_v01.py': {'path': 'source/reference/hedgehog/kernel/abi_v01.py', 'sha256': 'cc1a660a3cdceb5c30728b27016e99a752561969d744744d55b18ce0af398d31'}, 'source/reference/hedgehog/kernel/conformance_v01.py': {'path': 'source/reference/hedgehog/kernel/conformance_v01.py', 'sha256': '6cb61b29d37d4591d2da8dc10d7182d7a6c61010080415d58848a215718f6e2f'}, 'source/reference/hedgehog/kernel/continuous_delta_runtime_v01.py': {'path': 'source/reference/hedgehog/kernel/continuous_delta_runtime_v01.py', 'sha256': '879abad289ebae13b65cd0d2c5858e89f55fb059fecb111cde61d37f575a6af0'}, 'source/reference/hedgehog/kernel/effect_firewall_v01.py': {'path': 'source/reference/hedgehog/kernel/effect_firewall_v01.py', 'sha256': '46a453e0ef98565f0de59ab062b307eff6549a716973268a034592a5f98463bd'}, 'source/reference/hedgehog/kernel/execution_mode_router_v01.py': {'path': 'source/reference/hedgehog/kernel/execution_mode_router_v01.py', 'sha256': '4b19de7348a15cd65f1bed02bd93d848ccc490b6c7b8fe21338c3784809f79c4'}, 'source/reference/hedgehog/kernel/fractal_runtime_v02.py': {'path': 'source/reference/hedgehog/kernel/fractal_runtime_v02.py', 'sha256': 'ac946801b15c7464dd228034f64f0849c9567a71328ba50f3df314fe433dd0ba'}, 'source/reference/hedgehog/kernel/integrity_replay_v01.py': {'path': 'source/reference/hedgehog/kernel/integrity_replay_v01.py', 'sha256': 'd496354e7dbca5ff9c96943fe0d4bf777e85a88b404b67c7dfcfda116ee8d0be'}, 'source/reference/hedgehog/kernel/multiroot_v01.py': {'path': 'source/reference/hedgehog/kernel/multiroot_v01.py', 'sha256': 'e29137031417927e98c86b808e8e3897987a32ff953bbd6adcd6b4a7367e03ff'}, 'source/reference/hedgehog/kernel/root_decision_v01.py': {'path': 'source/reference/hedgehog/kernel/root_decision_v01.py', 'sha256': 'cae47026ba5c8a52ca25b2774e7ac8e92eb4e312c2eb5d1776c3a16ee276409c'}, 'source/reference/hedgehog/kernel/root_signer_isolation_v01.py': {'path': 'source/reference/hedgehog/kernel/root_signer_isolation_v01.py', 'sha256': '3f4efab32cd972803e61b0877c56d46eead9907611e1a1534b8cf924ba8c22f8'}, 'source/reference/hedgehog/kernel/semantic_work_v01.py': {'path': 'source/reference/hedgehog/kernel/semantic_work_v01.py', 'sha256': '34e6064cf62fda3b0b60ebc4f60cfdc963f3a609dfb9bd5d446c5b5bdd4c45b1'}, 'source/reference/hedgehog/kernel/transition_registry_v01.py': {'path': 'source/reference/hedgehog/kernel/transition_registry_v01.py', 'sha256': '16d2d3c31004bccc3064c74290bad4a7303669b63c428cebf6be8763574ae0ca'}, 'source/reference/hedgehog/kernel/trust_model_v01.py': {'path': 'source/reference/hedgehog/kernel/trust_model_v01.py', 'sha256': '6a1651bd624c78a09bfb433e3af8610d0033833d373b881e732da39381b65b2d'}, 'source/reference/hedgehog/kernel/work_composition_v01.py': {'path': 'source/reference/hedgehog/kernel/work_composition_v01.py', 'sha256': '1f068c0d1156a312f36a7e55b7cbaf0e3e84503168b3305e10420bd8e3d3cbf0'}, 'source/reference/hedgehog/local_drs_resolver.py': {'path': 'source/reference/hedgehog/local_drs_resolver.py', 'sha256': '5fa06d3cd243f6ef8cfd87997596413654ef03efac27e622ac9093659aea99a4'}, 'source/reference/hedgehog/local_drs_v02.py': {'path': 'source/reference/hedgehog/local_drs_v02.py', 'sha256': '831c3c7e0a1bfcb2ad9cc56d61c2c33ccbc8982add7ac46434c55676c03a34af'}, 'source/reference/hedgehog/outcome_calibration_v01.py': {'path': 'source/reference/hedgehog/outcome_calibration_v01.py', 'sha256': 'ce4a29c7dfe0f536b53fce8435ac584509681bf1cef4511d46ac0bfd48e05079'}, 'source/reference/hedgehog/outcome_feedback_consumer_v01.py': {'path': 'source/reference/hedgehog/outcome_feedback_consumer_v01.py', 'sha256': '19eab88fc949ccd10db1143c408224d48a82161527292b7b1283456fd0bd4938'}, 'source/reference/hedgehog/outcome_feedback_history_v01.py': {'path': 'source/reference/hedgehog/outcome_feedback_history_v01.py', 'sha256': 'aee1d5ed5649fcd877443dbca1a05f2bed38d1c2619cc84f31a1d8d99fb772b6'}, 'source/reference/hedgehog/outcome_feedback_v01.py': {'path': 'source/reference/hedgehog/outcome_feedback_v01.py', 'sha256': '16331fc98dc00f0d1e3bc1fff9ac65d15e555c0db1d7a3f2262a92d8acfd5a13'}, 'source/reference/hedgehog/post_vv.py': {'path': 'source/reference/hedgehog/post_vv.py', 'sha256': 'e2e856a3976a7250b738231aa62c39f1312278e6e6108e903ad363f87d7fcbe3'}, 'source/reference/hedgehog/reuse_certificate_v01.py': {'path': 'source/reference/hedgehog/reuse_certificate_v01.py', 'sha256': '55a061a0e225ae479d06380a9f47ac4e3d22f5771ad0fc24c0f4a0bdc73c852c'}, 'source/reference/hedgehog/reuse_gate.py': {'path': 'source/reference/hedgehog/reuse_gate.py', 'sha256': '964bd4ae925c934710f1055514a256b2a5d7521e91841628180c418742df9584'}, 'source/reference/hedgehog/semantic_reasoning_adapter.py': {'path': 'source/reference/hedgehog/semantic_reasoning_adapter.py', 'sha256': '3900b23d3f15ee42b21b7f28895e1badf6639d56a98ce3fcbe5a9f9c072009f6'}, 'source/reference/hedgehog/structured_rationale.py': {'path': 'source/reference/hedgehog/structured_rationale.py', 'sha256': '05686cd42bc4ea0bd9b0bc2586c7df6fd51369d43ee0fb15af4c95326e3d1f03'}, 'source/reference/hedgehog/time_model.py': {'path': 'source/reference/hedgehog/time_model.py', 'sha256': '1b461cf013f2e60a82509669b0ac692d0121b8d5f3c9d3a46a3d5fd33fc48cba'}, 'source/reference/hedgehog/wasm_pure_worker_v01.py': {'path': 'source/reference/hedgehog/wasm_pure_worker_v01.py', 'sha256': 'e9d727f3f971d5429fdffe25b0917548f2e903b63f1922a3bc60f9cb33e6d3ae'}, 'source/reference/hedgehog/work_execution_host_v01.py': {'path': 'source/reference/hedgehog/work_execution_host_v01.py', 'sha256': '56b7ba85e8612df517d566418fa60a2512bcf9f6707877618a3d846010e6071b'}, 'source/reference/schemas/capability_admission_v01.schema.json': {'path': 'source/reference/schemas/capability_admission_v01.schema.json', 'sha256': 'b09ac99cb2e62ffd95098401a5695a0f018d87d4f2e61f9de723f710ac7455e0'}, 'source/reference/schemas/common.schema.json': {'path': 'source/reference/schemas/common.schema.json', 'sha256': '961e73333fe62a7d935c7951a1104f1eb02ed7a20cf36c5e7df6d74e6d4d7880'}, 'source/reference/schemas/result_proposal.schema.json': {'path': 'source/reference/schemas/result_proposal.schema.json', 'sha256': 'd880876a28a03cd586db8f84d3c5c27a40ca526b9a4b8438f62894ef0d75b382'}, 'source/reference/schemas/time_envelope.schema.json': {'path': 'source/reference/schemas/time_envelope.schema.json', 'sha256': 'fffa05739e3eeed6d4cc6b4342d8833d6435aa8e9edbdfdafb96e5a7f3a99424'}, 'source/reference/schemas/vv_report.schema.json': {'path': 'source/reference/schemas/vv_report.schema.json', 'sha256': '44d9db2f5046e39178acc1461a93c670870fae0a2c71db79d61dfd5e193f4854'}, 'source/reference/schemas/work_composition_v01.schema.json': {'path': 'source/reference/schemas/work_composition_v01.schema.json', 'sha256': 'ac385c7202e39c88890d66fd148c85bfafe35e9c8f79ec9748866be39e6ba6a0'}, 'source/reference/specs/current_architecture_lock_v01.md': {'path': 'source/reference/specs/current_architecture_lock_v01.md', 'sha256': '0e122424aa2cd7f6b3156596f7038d4b46a5d9fc9b4c0962b565730ea5164682'}, 'source/reference/specs/document_authority_index_v01.json': {'path': 'source/reference/specs/document_authority_index_v01.json', 'sha256': '346c9bb839abc5c24f4bf55a02d46f6dae45ec87e9008ae48918aaa6a8b91d48'}}


def require(value, code):
    if not value:
        raise ValueError(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode('utf-8')


def digest(value):
    return hashlib.sha256(value if type(value) is bytes else canonical(value)).hexdigest()


def read(project, relative, *, cap=4 * 1024 * 1024):
    from review.transport import model_scope as base
    return base.read_public(project, relative, cap=cap)


def _json(project, relative):
    raw = read(project, relative)
    value = json.loads(raw)
    require(type(value) is dict, 'console_continuation_document_shape')
    return raw, value


def actual_basis(project):
    """Re-read only finite copied public evidence and the sealed old source set."""
    values = {}
    for relative, pin in ACTUAL_PINS.items():
        raw = read(project, relative)
        require(digest(raw) == pin, 'console_continuation_actual_pin')
        values[relative] = json.loads(raw) if relative.endswith('.json') else raw
    for relative, reference in HISTORICAL_SOURCE_FILES.items():
        require(digest(read(project, reference['path'])) == reference['sha256'],
            'console_continuation_historical_source_changed')
    ledger = values[ACTUAL_LEDGER]
    row = ledger['attempts'][-1]
    observation = values[ACTUAL_RESULT]
    reserved = values[ACTUAL_RESERVED]
    body = observation['request_body']
    context = json.loads(body['input'][0]['content'][0]['text'])
    require(len(ledger['attempts']) == 4 and ledger['version'] == LEGACY_VERSION
        and digest({key: value for key, value in ledger.items() if key != 'ledger_sha256'}) == OLD_HEAD
        and ledger['ledger_sha256'] == OLD_HEAD and ledger['active_attempt_id'] == ATTEMPT_ID
        and row['attempt_id'] == ATTEMPT_ID and row['owner_operation_id'] == OLD_OPERATION
        and row['run_id'] == OLD_RUN and row['outcome'] == row['usage'] == row['served_model'] == 'UNKNOWN'
        and row['context_sha256'] == CONTEXT_SHA and row['telemetry']['response_id'] == RESPONSE_ID
        and row['telemetry']['wire_body_sha256'] == BODY_SHA
        and row['telemetry']['terminal_observed'] is False,
        'console_continuation_actual_attempt')
    require(observation['reservation_id'] == reserved['reservation_id'] == ATTEMPT_ID
        and observation['response_id'] == RESPONSE_ID
        and observation['context_sha256'] == reserved['context_sha256'] == CONTEXT_SHA
        and digest(context) == CONTEXT_SHA and digest(body) == BODY_SHA
        and body == reserved['request_body'] and body['store'] is False
        and observation['wire']['body_sha256'] == reserved['wire']['body_sha256'] == BODY_SHA
        and observation['source_identity_sha256'] == reserved['source_identity_sha256'] == OLD_SOURCE
        and observation['client_http_closed'] is observation['deadline_watchdog_finished'] is True
        and observation['terminal_observed'] is False and observation['usage'] == 'UNKNOWN'
        and observation['outcome'] == 'UNKNOWN' and observation['error_code'] == 'plan_unexpected_stream_event'
        and observation['completed_output']['role_product_accepted'] is False,
        'console_continuation_actual_cleanup')
    runtime = values[OLD_RUNTIME_REVIEW]
    owner = values[OLD_OWNER_REVIEW]
    require(digest(runtime['pins']) == OLD_SOURCE and digest(owner['pins']) == OLD_AUTH
        and set(runtime['pins']) == set(HISTORICAL_SOURCE_FILES)
        and all(runtime['pins'][name] == reference['sha256'] for name, reference in HISTORICAL_SOURCE_FILES.items()),
        'console_continuation_actual_source')
    return ledger


def _proposal(project):
    raw, value = _json(project, PROPOSAL)
    require(value == dict(schema='radik.console_local_continuation_proposal.v01',
        scope='LOCAL_OCCUPANCY_ONLY_REMOTE_UNKNOWN_PRESERVED', actual_attempt_id=ATTEMPT_ID,
        response_id=RESPONSE_ID, context_sha256=CONTEXT_SHA, body_sha256=BODY_SHA,
        old_ledger_raw_sha256=OLD_RAW, old_ledger_canonical_sha256=OLD_HEAD,
        old_source_identity_sha256=OLD_SOURCE, old_auth_source_identity_sha256=OLD_AUTH,
        actual_evidence_pins=ACTUAL_PINS, historical_source_files=HISTORICAL_SOURCE_FILES,
        receipt_path=RECEIPT, ledger_version=VERSION, historical_prefix_count=4,
        immutable_outcome='UNKNOWN', immutable_usage='UNKNOWN', server_outcome='UNKNOWN',
        authorization='FUTURE_EXPLICIT_OWNER_COMMAND_ONLY', automatic_retry=False,
        entry_authorizes_model_or_effect=False), 'console_continuation_proposal')
    return raw


def approval(project, *, historical=False):
    """A source-only seal is necessary; it does not acknowledge an attempt."""
    proposal_raw = _proposal(project)
    raw, value = _json(project, REVIEW)
    require(set(value) == {'schema', 'reviewer', 'status', 'scope', 'proposal_sha256',
        'source_identity_sha256', 'auth_source_identity_sha256', 'runtime_review_sha256',
        'owner_review_sha256', 'actual_evidence_pins', 'entry_authorizes_model_or_effect'}
        and value['schema'] == 'radik.independent.console_local_continuation_review.v01'
        and value['reviewer'] == '/root/semantic_continuation_reviewer'
        and value['status'] == 'SOURCE_ACCEPTED_FOR_EXPLICIT_CONSOLE_LOCAL_CONTINUATION'
        and value['scope'] == 'LOCAL_OCCUPANCY_ONLY_REMOTE_UNKNOWN_PRESERVED'
        and value['proposal_sha256'] == digest(proposal_raw)
        and value['actual_evidence_pins'] == ACTUAL_PINS
        and value['entry_authorizes_model_or_effect'] is False,
        'console_continuation_independent_review')
    runtime_raw, runtime = _json(project, RUNTIME_REVIEW)
    owner_raw, owner = _json(project, OWNER_REVIEW)
    require(digest(runtime_raw) == value['runtime_review_sha256']
        and digest(owner_raw) == value['owner_review_sha256']
        and runtime.get('reviewer') == owner.get('reviewer') == '/root/semantic_continuation_reviewer'
        and runtime.get('status') == 'SOURCE_ACCEPTED_FOR_BOUNDED_LIVE_TRANSITION'
        and owner.get('status') == 'SOURCE_ACCEPTED_FOR_OWNER_AUTH_PREFLIGHT'
        and runtime.get('scope') == owner.get('scope') == 'DIRECT_CHATGPT_PLAN_SOURCE_ONLY'
        and digest(runtime['pins']) == value['source_identity_sha256']
        and digest(owner['pins']) == value['auth_source_identity_sha256']
        and set(owner['pins']) <= set(runtime['pins'])
        and all(runtime['pins'][name] == pin for name, pin in owner['pins'].items()),
        'console_continuation_review_source_binding')
    resolution=None
    if historical:
        basis_raw,basis=_json(project,LEGACY_SOURCE_RESOLUTION)
        require(digest(basis_raw)==LEGACY_SOURCE_RESOLUTION_SHA
            and basis.get('reviewer')=='/root/semantic_continuation_reviewer'
            and basis.get('historical_source_identity_sha256')==value['source_identity_sha256']
            and basis.get('historical_AUTH_identity_sha256')==value['auth_source_identity_sha256'],
            'console_continuation_historical_review')
        resolution=basis['historical_source_resolution']
        require(set(resolution)==set(runtime['pins']),'console_continuation_historical_review')
    for relative,pin in runtime['pins'].items():
        reference=resolution[relative] if resolution is not None else dict(path=relative,sha256=pin)
        require(reference['sha256']==pin and digest(read(project,reference['path']))==pin,
            'console_continuation_historical_source_changed' if historical else 'console_continuation_current_source_changed')
    return raw,value


def _validate_legacy(project, ledger):
    """Recognize one historical UNKNOWN; all other unsettled rows remain active."""
    from review.transport import model_scope as base
    path = base.owned(project, RECEIPT)
    if ledger.get('version') == LEGACY_VERSION:
        require('console_continuation_ref' not in ledger and not path.exists(),
            'console_continuation_incomplete')
        return dict(acknowledged_remote_unknown_attempt_ids=[], local_occupancy_released=False,
            remote_outcome='UNKNOWN' if any(row.get('outcome') == 'UNKNOWN' for row in ledger['attempts']) else 'NOT_APPLICABLE',
            continuation_receipt_ref=None)
    require(ledger.get('version') == VERSION, 'console_continuation_version')
    reference = ledger.get('console_continuation_ref')
    require(type(reference) is dict and set(reference) == {'path', 'sha256'}
        and reference['path'] == RECEIPT and base.is_hash(reference['sha256']),
        'console_continuation_receipt_reference')
    raw, value = _json(project, RECEIPT)
    require(raw == canonical(value) and digest(raw) == reference['sha256'],
        'console_continuation_receipt_pin')
    before = actual_basis(project)
    review_raw, review = approval(project,historical=True)
    require(set(value) == RECEIPT_FIELDS and value['schema'] == RECEIPT_VERSION
        and value['receipt_sha256'] == digest({key: item for key, item in value.items() if key != 'receipt_sha256'})
        and value['disposition'] == 'LOCAL_OCCUPANCY_RELEASED_REMOTE_OUTCOME_UNKNOWN'
        and value['attempt_id'] == ATTEMPT_ID and value['response_id'] == RESPONSE_ID
        and value['old_ledger_raw_sha256'] == OLD_RAW and value['old_ledger_canonical_sha256'] == OLD_HEAD
        and value['historical_prefix_sha256'] == digest(before['attempts'])
        and value['context_sha256'] == CONTEXT_SHA and value['body_sha256'] == BODY_SHA
        and value['local_http_closed'] is value['local_watchdog_finished'] is True
        and value['remote_outcome'] == value['usage'] == 'UNKNOWN'
        and value['automatic_retry'] is value['server_cancellation_observed'] is False
        and value['source_identity_sha256'] == review['source_identity_sha256']
        and value['auth_source_identity_sha256'] == review['auth_source_identity_sha256']
        and value['review_ref'] == dict(path=REVIEW, sha256=digest(review_raw))
        and type(value['owner_operation_id']) is str
        and re.fullmatch('[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', value['owner_operation_id'])
        and value['owner_operation_id'] != OLD_OPERATION
        and type(value['run_id']) is str and re.fullmatch('[0-9a-f]{12}', value['run_id'])
        and value['run_id'] != OLD_RUN
        and all(value['owner_operation_id'] != row['owner_operation_id']
            and value['run_id'] != row['run_id'] for row in before['attempts'])
        and type(value['recorded_at']) is int
        and value['recorded_at'] >= before['attempts'][3]['finished_at'],
        'console_continuation_receipt_binding')
    require(ledger['attempts'][:4] == before['attempts']
        and {key: item for key, item in ledger.items() if key not in
            ('version', 'attempts', 'active_attempt_id', 'ledger_sha256', 'console_continuation_ref')}
        == {key: item for key, item in before.items() if key not in
            ('version', 'attempts', 'active_attempt_id', 'ledger_sha256')},
        'console_continuation_prefix_changed')
    if len(ledger['attempts']) > 4:
        first = ledger['attempts'][4]
        require(first['owner_operation_id'] == value['owner_operation_id']
            and first['run_id'] == value['run_id']
            and first['round_binding']['round_id'] != before['attempts'][3]['round_binding']['round_id'],
            'console_continuation_first_reservation_binding')
    return dict(acknowledged_remote_unknown_attempt_ids=[ATTEMPT_ID],
        local_occupancy_released=True, remote_outcome='UNKNOWN',
        continuation_receipt_ref=dict(reference), continuation_owner_operation_id=value['owner_operation_id'],
        continuation_run_id=value['run_id'])


def assert_reservation(project, ledger, *, owner_operation_id, run_id, round_id):
    checked = validate(project, ledger)
    if checked.get('operation_allowance') is not None:
        require(owner_operation_id==checked['continuation_owner_operation_id']
            and run_id==checked['continuation_run_id'] if len(ledger['attempts'])==checked['continuation_prefix_count'] else True,
            'console_continuation_first_reservation_binding')
        return
    if checked['local_occupancy_released'] and len(ledger['attempts']) == 4:
        require(owner_operation_id == checked['continuation_owner_operation_id']
            and run_id == checked['continuation_run_id']
            and round_id != ledger['attempts'][3]['round_binding']['round_id'],
            'console_continuation_first_reservation_binding')


def _owner_lock(project, owner_lock_fd):
    from review.transport import model_scope as base
    require(type(owner_lock_fd) is int and owner_lock_fd >= 0, 'console_continuation_owner_lock')
    path = base.owned(project, base.OWNER_LOCK_PATH)
    info, selected = os.fstat(owner_lock_fd), path.stat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
        and stat.S_IMODE(info.st_mode) == 0o600 and info.st_uid == os.getuid()
        and (info.st_dev, info.st_ino) == (selected.st_dev, selected.st_ino),
        'console_continuation_owner_lock')
    fcntl.flock(owner_lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)


def _sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def apply(project, *, owner_lock_fd, owner_operation_id, run_id,
          source_identity_sha256, auth_source_identity_sha256):
    """A future explicit owner command may acknowledge local closure once.

    A crash after receipt creation refuses further use. This function never
    repairs an incomplete acknowledgement, resets a count, or starts a request.
    """
    from review.transport import model_scope as base
    from . import task_budget
    project = Path(project).resolve(strict=True)
    _owner_lock(project, owner_lock_fd)
    require(type(owner_operation_id) is str and re.fullmatch(
        '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', owner_operation_id)
        and owner_operation_id != OLD_OPERATION and type(run_id) is str
        and re.fullmatch('[0-9a-f]{12}', run_id) and run_id != OLD_RUN,
        'console_continuation_new_operation')
    receipt_path = base.owned(project, RECEIPT)
    require(not receipt_path.exists(), 'console_continuation_already_applied_or_incomplete')
    review_raw, review = approval(project)
    require(source_identity_sha256 == review['source_identity_sha256']
        and auth_source_identity_sha256 == review['auth_source_identity_sha256'],
        'console_continuation_current_source_binding')
    before = actual_basis(project)
    require(all(owner_operation_id != row['owner_operation_id'] and run_id != row['run_id']
        for row in before['attempts']), 'console_continuation_new_operation')
    ledger_path = base.owned(project, base.SCOPE_PATHS['console']['ledger'])
    lock_path = ledger_path.with_suffix('.lock')
    require(lock_path.exists() and not lock_path.is_symlink(), 'console_continuation_ledger_lock')
    fd = os.open(lock_path, os.O_RDWR | os.O_NOFOLLOW)
    with os.fdopen(fd, 'a+b') as lock:
        info = os.fstat(lock.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
            and info.st_uid == os.getuid(), 'console_continuation_ledger_lock')
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        state = task_budget.read_state(project)
        raw, ledger = _json(project, base.SCOPE_PATHS['console']['ledger'])
        require(raw == canonical(ledger) and digest(raw) == OLD_RAW and ledger == before
            and state['active_attempt_id'] == ATTEMPT_ID and state['counted'] == 4
            and state['source_identity_sha256'] == source_identity_sha256
            and state['auth_source_identity_sha256'] == auth_source_identity_sha256,
            'console_continuation_current_ledger_changed')
        receipt = dict(schema=RECEIPT_VERSION,
            disposition='LOCAL_OCCUPANCY_RELEASED_REMOTE_OUTCOME_UNKNOWN', attempt_id=ATTEMPT_ID,
            response_id=RESPONSE_ID, old_ledger_raw_sha256=OLD_RAW,
            old_ledger_canonical_sha256=OLD_HEAD, historical_prefix_sha256=digest(before['attempts']),
            context_sha256=CONTEXT_SHA, body_sha256=BODY_SHA, local_http_closed=True,
            local_watchdog_finished=True, remote_outcome='UNKNOWN', usage='UNKNOWN',
            automatic_retry=False, server_cancellation_observed=False,
            source_identity_sha256=source_identity_sha256,
            auth_source_identity_sha256=auth_source_identity_sha256,
            review_ref=dict(path=REVIEW, sha256=digest(review_raw)),
            owner_operation_id=owner_operation_id, run_id=run_id, recorded_at=int(time.time()))
        receipt['receipt_sha256'] = digest(receipt)
        receipt_raw = canonical(receipt)
        ledger.update(version=VERSION, active_attempt_id=None,
            console_continuation_ref=dict(path=RECEIPT, sha256=digest(receipt_raw)))
        ledger['ledger_sha256'] = digest({key: item for key, item in ledger.items() if key != 'ledger_sha256'})
        pending = ledger_path.with_suffix('.pending')
        require(not pending.exists() and not pending.is_symlink(), 'console_continuation_pending_write')
        fd = os.open(receipt_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(receipt_raw); stream.flush(); os.fsync(stream.fileno())
        _sync_directory(receipt_path.parent)
        require(read(project, RECEIPT) == receipt_raw, 'console_continuation_receipt_readback')
        # Validate the exact intended pair before publishing the new header.
        _settings_raw, settings = task_budget.read_json(project, task_budget.SETTINGS)
        _record_raw, transition = task_budget.read_json(project, task_budget.TRANSITION)
        task_budget.validate_ledger(project, ledger, transition, settings)
        fd = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(canonical(ledger)); stream.flush(); os.fsync(stream.fileno())
        os.replace(pending, ledger_path)
        _sync_directory(ledger_path.parent)
        after = task_budget.read_state(project)
        require(after['counted'] == 4 and after['active_attempt_id'] is None
            and read(project, base.SCOPE_PATHS['console']['ledger']) == canonical(ledger)
            and after['acknowledged_remote_unknown_attempt_ids'] == [ATTEMPT_ID],
            'console_continuation_ledger_readback')
        return dict(receipt_ref=ledger['console_continuation_ref'], owner_operation_id=owner_operation_id,
            run_id=run_id, counted=4, local_occupancy_released=True, server_outcome='UNKNOWN',
            new_request_started=False)

# The original v01 constants and documents above remain historical identities.
CURRENT_PASSAGE='review/opaque_metadata_passage'
CURRENT_PROPOSAL=CURRENT_PASSAGE+'/continuation_proposal.json'
CURRENT_REVIEW=CURRENT_PASSAGE+'/continuation_review.json'
CHAIN_VERSION='radik.console_turn_ledger.v04'
TYPED_PROPOSAL_VERSION='radik.console_local_continuation_proposal.v02'
TYPED_RECEIPT_VERSION='radik.console_local_continuation_receipt.v02'
ALLOWANCE_VERSION='radik.console_operation_allowance.v01'
ROUND_ALLOWANCE_VERSION='radik.console_operation_round.v01'
RELATIVE_ALLOWANCE_VERSION='radik.console_operation_allowance.v02'
RELATIVE_ROUND_ALLOWANCE_VERSION='radik.console_operation_round.v02'
LEGACY_SOURCE_RESOLUTION='review/metadata_continuation_passage/baseline_review.json'
LEGACY_SOURCE_RESOLUTION_SHA='f4928ac0ba1fa7ecb3b7ead1ff25731cb6da27092bd236f97054e37f6ca87220'
ACTION_IDS=('A_COLD','B_COLD','A_CURRENT_MEMORY','C_VERIFY')
MAX_RECEIPTS=16
BASE_ROUND_LIMIT=3


def _ref(value, *, receipt=False):
    require(type(value)is dict and set(value)=={'path','sha256'}
        and type(value['path'])is str and type(value['sha256'])is str
        and re.fullmatch('[0-9a-f]{64}',value['sha256'])
        and (re.fullmatch(r'state/console_continuations/[0-9a-f]{32}\.json',value['path']) is not None
            if receipt else value['path'].startswith('review/') and not Path(value['path']).is_absolute())
        and not set(Path(value['path']).parts).intersection(('.', '..','private','.aws','.codex','Arena','arena')),
        'console_continuation_typed_reference')
    return value


def _ref_json(project,reference,*,receipt=False):
    _ref(reference,receipt=receipt)
    raw,value=_json(project,reference['path'])
    require(digest(raw)==reference['sha256'],'console_continuation_typed_reference_pin')
    return raw,value


def _legacy_allowance_shape(value,before_tasks):
    require(type(value)is dict and set(value)=={'schema','task_ids','actions','native_u2_max_revisions',
        'native_work_provider_calls','native_E_provider_calls'}
        and value['schema']==ALLOWANCE_VERSION and type(value['task_ids'])is dict
        and set(value['task_ids'])=={'a','b','c'} and len(set(value['task_ids'].values()))==3
        and set(value['task_ids'].values())<=set(before_tasks['tasks'])
        and type(value['actions'])is list and 1<=len(value['actions'])<=4
        and type(value['native_u2_max_revisions'])is int and value['native_u2_max_revisions']==2
        and type(value['native_work_provider_calls'])is int and type(value['native_E_provider_calls'])is int
        and value['native_work_provider_calls']==value['native_E_provider_calls']==0,
        'console_allowance_shape')
    positions=[];counts={tid:sum(event['kind']=='ROUND_STARTED' for event in before_tasks['tasks'][tid]['history'])
        for tid in value['task_ids'].values()}
    for index,action in enumerate(value['actions']):
        require(type(action)is dict and set(action)=={'action_id','task_id','mode','max_provider_attempts','lifetime_round'}
            and action['action_id'] in ACTION_IDS,'console_allowance_action')
        label=action['action_id'];positions.append(ACTION_IDS.index(label))
        key='a' if label in ('A_COLD','A_CURRENT_MEMORY') else 'b' if label=='B_COLD' else 'c'
        counts[action['task_id']]=counts.get(action['task_id'],0)+1
        require(action['task_id']==value['task_ids'][key]
            and action['mode']==('MEMORY_ONLY' if label=='A_CURRENT_MEMORY' else 'COLD')
            and type(action['max_provider_attempts'])is int
            and action['max_provider_attempts']==(0 if label=='A_CURRENT_MEMORY' else 3)
            and type(action['lifetime_round'])is int and action['lifetime_round']==counts[action['task_id']]
            and action['lifetime_round']<=(4 if action['mode']=='MEMORY_ONLY' else BASE_ROUND_LIMIT),
            'console_allowance_action')
    require(positions==sorted(set(positions)),'console_allowance_action_order')
    return value


def _relative_allowance_shape(value,before_tasks):
    """Finite permission relative to immutable history, never a lifetime quota."""
    require(type(value)is dict and set(value)=={'schema','task_ids','actions','native_u2_max_revisions',
        'native_work_provider_calls','native_E_provider_calls','max_provider_reservations'}
        and value['schema']==RELATIVE_ALLOWANCE_VERSION and type(value['task_ids'])is dict
        and set(value['task_ids'])=={'a','b','c'} and len(set(value['task_ids'].values()))==3
        and set(value['task_ids'].values())<=set(before_tasks['tasks'])
        and type(value['actions'])is list and 1<=len(value['actions'])<=4
        and type(value['native_u2_max_revisions'])is int and value['native_u2_max_revisions']==2
        and type(value['native_work_provider_calls'])is int and type(value['native_E_provider_calls'])is int
        and value['native_work_provider_calls']==value['native_E_provider_calls']==0
        and type(value['max_provider_reservations'])is int and 0<=value['max_provider_reservations']<=9,
        'console_relative_allowance_shape')
    positions=[];prior=[];counts={tid:sum(event['kind']=='ROUND_STARTED' for event in
        before_tasks['tasks'][tid]['history']) for tid in value['task_ids'].values()}
    initial=dict(counts)
    fields={'action_id','task_id','mode','max_provider_attempts','lifetime_round','task_spec_sha256',
        'before_round_count','before_history_sha256','action_ordinal','predecessor_action_id','memory_result_action_id'}
    for index,action in enumerate(value['actions']):
        require(type(action)is dict and set(action)==fields and action['action_id'] in ACTION_IDS
            and action['task_id'] in initial,'console_relative_allowance_action')
        label=action['action_id'];tid=action['task_id'];positions.append(ACTION_IDS.index(label));counts[tid]+=1
        key='a' if label in ('A_COLD','A_CURRENT_MEMORY') else 'b' if label=='B_COLD' else 'c'
        row=before_tasks['tasks'][tid];mode='MEMORY_ONLY' if label=='A_CURRENT_MEMORY' else 'COLD'
        require(tid==value['task_ids'][key] and action['mode']==mode
            and type(action['max_provider_attempts'])is int and action['max_provider_attempts']==(0 if mode=='MEMORY_ONLY' else 3)
            and type(action['before_round_count'])is int and action['before_round_count']==initial[tid]
            and action['before_history_sha256']==digest(row['history'])
            and action['task_spec_sha256']==digest(row['spec'])
            and type(action['lifetime_round'])is int and action['lifetime_round']==counts[tid]
            and type(action['action_ordinal'])is int and action['action_ordinal']==index+1
            and action['predecessor_action_id']==(None if not prior else prior[-1]['action_id']),
            'console_relative_allowance_action')
        if mode=='MEMORY_ONLY':
            anchor=[item for item in prior if item['action_id']==action['memory_result_action_id']]
            require(len(anchor)==1 and anchor[0]['task_id']==tid and anchor[0]['mode']=='COLD',
                'console_relative_allowance_memory_predecessor')
        else:require(action['memory_result_action_id'] is None,'console_relative_allowance_memory_predecessor')
        prior.append(action)
    require(positions==sorted(set(positions))
        and sum(action['max_provider_attempts'] for action in value['actions'])==value['max_provider_reservations'],
        'console_relative_allowance_order_or_reservations')
    return value


def _allowance_shape(value,before_tasks):
    if type(value)is dict and value.get('schema')==RELATIVE_ALLOWANCE_VERSION:
        return _relative_allowance_shape(value,before_tasks)
    return _legacy_allowance_shape(value,before_tasks)


def typed_proposal(project, reference=None):
    """Read a closed proposal; raw documents never become implicit authority."""
    if reference is None:
        raw,value=_json(project,CURRENT_PROPOSAL)
        reference=dict(path=CURRENT_PROPOSAL,sha256=digest(raw))
    else:raw,value=_ref_json(project,reference)
    fields={'schema','scope','before_ledger_ref','before_task_state_ref','selected_attempt_id',
        'transport_result_ref','previous_receipt_refs','actual_evidence_pins','historical_source_basis',
        'source_basis','receipt_path','operation_allowance','automatic_retry','entry_authorizes_model_or_effect'}
    require(set(value)==fields and value['schema']==TYPED_PROPOSAL_VERSION
        and value['scope']=='SELECTED_LOCAL_UNKNOWN_AND_EXACT_PROPOSED_ACTIONS_ONLY'
        and type(value['previous_receipt_refs'])is list and 1<=len(value['previous_receipt_refs'])<MAX_RECEIPTS
        and type(value['actual_evidence_pins'])is dict and 1<=len(value['actual_evidence_pins'])<=512
        and value['automatic_retry'] is value['entry_authorizes_model_or_effect'] is False,
        'console_continuation_typed_proposal')
    for path,pin in value['actual_evidence_pins'].items():
        _ref(dict(path=path,sha256=pin))
        require(digest(read(project,path))==pin,'console_continuation_typed_actual_pin')
    before_raw,before=_ref_json(project,value['before_ledger_ref'])
    _tasks_raw,tasks=_ref_json(project,value['before_task_state_ref'])
    _result_raw,result=_ref_json(project,value['transport_result_ref'])
    require(before_raw==canonical(before) and type(before.get('attempts'))is list and 4<=len(before['attempts'])<=1000000
        and before['ledger_sha256']==digest({key:item for key,item in before.items() if key!='ledger_sha256'})
        and before['active_attempt_id']==value['selected_attempt_id'], 'console_continuation_typed_before_ledger')
    rows=[row for row in before['attempts'] if row['attempt_id']==value['selected_attempt_id']]
    require(len(rows)==1 and rows[0]['outcome']==rows[0]['usage']=='UNKNOWN',
        'console_continuation_typed_selected_unknown')
    row=rows[0]
    require(result.get('reservation_id')==row['attempt_id'] and result.get('outcome')=='UNKNOWN'
        and result.get('response_id')==row['telemetry']['response_id']
        and result.get('context_sha256')==row['context_sha256']
        and result.get('wire',{}).get('body_sha256')==row['telemetry']['wire_body_sha256']
        and digest(result['request_body'])==row['telemetry']['wire_body_sha256']
        and digest(json.loads(result['request_body']['input'][0]['content'][0]['text']))==row['context_sha256']
        and result['request_body']['store'] is False
        and result.get('client_http_closed') is result.get('deadline_watchdog_finished') is True
        and result.get('terminal_observed') is False and result.get('usage')=='UNKNOWN'
        and result.get('completed_output',{}).get('role_product_accepted') is False,
        'console_continuation_typed_cleanup')
    require(value['receipt_path']=='state/console_continuations/'+row['attempt_id'].split(':')[-1]+'.json',
        'console_continuation_typed_receipt_path')
    _allowance_shape(value['operation_allowance'],tasks)
    return reference,raw,value,before,tasks,result


def _source_basis(project,basis,*,current=False):
    require(type(basis)is dict and set(basis)=={'runtime_review_ref','owner_review_ref','source_files'},
        'console_continuation_typed_source_basis')
    _runtime_raw,runtime=_ref_json(project,basis['runtime_review_ref'])
    _owner_raw,owner=_ref_json(project,basis['owner_review_ref'])
    require(runtime.get('reviewer')==owner.get('reviewer')=='/root/semantic_continuation_reviewer'
        and runtime.get('status')=='SOURCE_ACCEPTED_FOR_BOUNDED_LIVE_TRANSITION'
        and owner.get('status')=='SOURCE_ACCEPTED_FOR_OWNER_AUTH_PREFLIGHT'
        and runtime.get('scope')==owner.get('scope')=='DIRECT_CHATGPT_PLAN_SOURCE_ONLY'
        and type(basis['source_files'])is dict and set(basis['source_files'])==set(runtime['pins'])
        and set(owner['pins'])<=set(runtime['pins'])
        and all(runtime['pins'][name]==pin for name,pin in owner['pins'].items()),
        'console_continuation_typed_source_basis')
    for name,pin in runtime['pins'].items():
        reference=basis['source_files'][name]
        require(type(reference)is dict and set(reference)=={'path','sha256'}
            and type(reference['path'])is str and not Path(reference['path']).is_absolute()
            and (reference['path']=='radik' or reference['path'].startswith(('app/','config/','review/','source/reference/')))
            and not set(Path(reference['path']).parts).intersection(('..','private','.aws','.codex','Arena','arena')),
            'console_continuation_typed_source_basis')
        require(reference['sha256']==pin and digest(read(project,reference['path']))==pin,
            'console_continuation_typed_source_changed')
        if current:require(digest(read(project,name))==pin,'console_continuation_current_source_changed')
    return digest(runtime['pins']),digest(owner['pins'])


def typed_approval(project,proposal_ref=None,review_ref=None,*,current=False):
    reference,raw,proposal,before,tasks,result=typed_proposal(project,proposal_ref)
    if review_ref is None:
        review_raw,review=_json(project,CURRENT_REVIEW)
        review_ref=dict(path=CURRENT_REVIEW,sha256=digest(review_raw))
    else:review_raw,review=_ref_json(project,review_ref)
    require(set(review)=={'schema','reviewer','status','scope','proposal_sha256','source_identity_sha256',
        'auth_source_identity_sha256','entry_authorizes_model_or_effect'}
        and review['schema']=='radik.independent.console_local_continuation_review.v02'
        and review['reviewer']=='/root/semantic_continuation_reviewer'
        and review['status']=='SOURCE_ACCEPTED_FOR_VERSIONED_CONSOLE_CONTINUATION_WITH_FINITE_ALLOWANCE'
        and review['scope']==proposal['scope'] and review['proposal_sha256']==digest(raw)
        and review['entry_authorizes_model_or_effect'] is False,'console_continuation_typed_review')
    B,A=_source_basis(project,proposal['source_basis'],current=current)
    old_B,_old_A=_source_basis(project,proposal['historical_source_basis'])
    require(B==review['source_identity_sha256'] and A==review['auth_source_identity_sha256']
        and old_B==result['source_identity_sha256'],'console_continuation_typed_review_binding')
    return reference,review_ref,proposal,before,tasks,result,review


def _legacy_view(ledger):
    return {key:(VERSION if key=='version' else item) for key,item in ledger.items()
        if key!='console_continuation_chain'}


def validate(project,ledger):
    """Validate an ordered receipt chain without constructing budgets or stores."""
    if ledger.get('version')=='radik.console_turn_ledger.v05':
        from .normal_session import historical_ledger
        ledger=historical_ledger(project,ledger)
    if ledger.get('version')!=CHAIN_VERSION:return _validate_legacy(project,ledger)
    refs=ledger.get('console_continuation_chain')
    require(type(refs)is list and 2<=len(refs)<=MAX_RECEIPTS
        and refs[0]==ledger.get('console_continuation_ref')
        and len({item.get('path') for item in refs if type(item)is dict})==len(refs),
        'console_continuation_chain_shape')
    checked=_validate_legacy(project,_legacy_view(ledger));acknowledged=list(checked['acknowledged_remote_unknown_attempt_ids'])
    latest=None
    for index,reference in enumerate(refs[1:],1):
        receipt_raw,receipt=_ref_json(project,reference,receipt=True)
        require(receipt_raw==canonical(receipt) and set(receipt)=={'schema','proposal_ref','review_ref',
            'previous_receipt_refs','selected_attempt_id','response_id','context_sha256','body_sha256',
            'before_ledger_sha256','before_ledger_canonical_sha256','historical_prefix_sha256',
            'source_identity_sha256','auth_source_identity_sha256','owner_operation_id','run_id','recorded_at',
            'local_http_closed','local_watchdog_finished','remote_outcome','usage','automatic_retry',
            'server_cancellation_observed','operation_allowance_sha256','receipt_sha256'},
            'console_continuation_chain_receipt_shape')
        prop_ref,review_ref,proposal,before,tasks,result,review=typed_approval(project,
            receipt['proposal_ref'],receipt['review_ref'])
        row=next(row for row in before['attempts'] if row['attempt_id']==proposal['selected_attempt_id'])
        require(receipt['schema']==TYPED_RECEIPT_VERSION
            and receipt['receipt_sha256']==digest({key:item for key,item in receipt.items() if key!='receipt_sha256'})
            and receipt['previous_receipt_refs']==proposal['previous_receipt_refs']==refs[:index]
            and reference['path']==proposal['receipt_path'] and receipt['selected_attempt_id']==row['attempt_id']
            and row['attempt_id'] not in acknowledged
            and receipt['response_id']==result['response_id'] and receipt['context_sha256']==row['context_sha256']
            and receipt['body_sha256']==row['telemetry']['wire_body_sha256']
            and receipt['before_ledger_sha256']==proposal['before_ledger_ref']['sha256']
            and receipt['before_ledger_canonical_sha256']==before['ledger_sha256']
            and receipt['historical_prefix_sha256']==digest(before['attempts'])
            and receipt['source_identity_sha256']==review['source_identity_sha256']
            and receipt['auth_source_identity_sha256']==review['auth_source_identity_sha256']
            and receipt['operation_allowance_sha256']==digest(proposal['operation_allowance'])
            and receipt['local_http_closed'] is receipt['local_watchdog_finished'] is True
            and receipt['remote_outcome']==receipt['usage']=='UNKNOWN'
            and receipt['automatic_retry'] is receipt['server_cancellation_observed'] is False
            and type(receipt['recorded_at'])is int and receipt['recorded_at']>=row['finished_at']
            and type(receipt['owner_operation_id'])is str and re.fullmatch('[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',receipt['owner_operation_id'])
            and type(receipt['run_id'])is str and re.fullmatch('[0-9a-f]{12}',receipt['run_id'])
            and all(receipt['owner_operation_id']!=old['owner_operation_id'] and receipt['run_id']!=old['run_id']
                for old in before['attempts'])
            and ledger['attempts'][:len(before['attempts'])]==before['attempts'],
            'console_continuation_chain_receipt_binding')
        before_refs=before.get('console_continuation_chain',[before.get('console_continuation_ref')])
        require(before_refs==refs[:index] and {key:item for key,item in ledger.items() if key not in
            ('version','attempts','active_attempt_id','ledger_sha256','console_continuation_chain')}
            =={key:item for key,item in before.items() if key not in
            ('version','attempts','active_attempt_id','ledger_sha256','console_continuation_chain')},
            'console_continuation_chain_prefix_changed')
        acknowledged.append(row['attempt_id'])
        latest=dict(reference=reference,receipt=receipt,proposal=proposal,before=before,tasks=tasks)
    require(latest is not None,'console_continuation_chain_shape')
    count=len(latest['before']['attempts']);receipt=latest['receipt']
    if len(ledger['attempts'])>count:
        first=ledger['attempts'][count]
        require(first['owner_operation_id']==receipt['owner_operation_id'] and first['run_id']==receipt['run_id'],
            'console_continuation_first_reservation_binding')
    return dict(acknowledged_remote_unknown_attempt_ids=acknowledged,local_occupancy_released=True,
        remote_outcome='UNKNOWN',continuation_receipt_ref=latest['reference'],continuation_receipt_chain=refs,
        continuation_owner_operation_id=receipt['owner_operation_id'],continuation_run_id=receipt['run_id'],
        continuation_prefix_count=count,operation_allowance=latest['proposal']['operation_allowance'],
        continuation_proposal_ref=receipt['proposal_ref'])


def apply_typed(project,proposal_ref=None,*,owner_lock_fd,owner_operation_id,run_id,
                source_identity_sha256,auth_source_identity_sha256):
    """Future explicit owner action appends one immutable selected acknowledgement."""
    from review.transport import model_scope as base
    from . import task_budget
    project=Path(project).resolve(strict=True);_owner_lock(project,owner_lock_fd)
    prop_ref,review_ref,proposal,before,tasks,result,review=typed_approval(project,proposal_ref,current=True)
    require(source_identity_sha256==review['source_identity_sha256']
        and auth_source_identity_sha256==review['auth_source_identity_sha256']
        and type(owner_operation_id)is str and re.fullmatch('[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',owner_operation_id)
        and type(run_id)is str and re.fullmatch('[0-9a-f]{12}',run_id)
        and all(owner_operation_id!=row['owner_operation_id'] and run_id!=row['run_id'] for row in before['attempts']),
        'console_continuation_new_operation')
    container=base.owned(project,'state/console_continuations')
    require(not container.is_symlink(),'console_continuation_typed_receipt_path')
    container.mkdir(mode=0o700,exist_ok=True)
    receipt_path=base.owned(project,proposal['receipt_path'])
    require(not receipt_path.exists(),'console_continuation_already_applied_or_incomplete')
    ledger_path=base.owned(project,base.SCOPE_PATHS['console']['ledger']);lock_path=ledger_path.with_suffix('.lock')
    require(lock_path.is_file() and not lock_path.is_symlink(),'console_continuation_ledger_lock')
    fd=os.open(lock_path,os.O_RDWR|os.O_NOFOLLOW)
    with os.fdopen(fd,'a+b') as lock:
        info=os.fstat(lock.fileno());require(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_uid==os.getuid(),
            'console_continuation_ledger_lock');fcntl.flock(lock.fileno(),fcntl.LOCK_EX)
        state=task_budget.read_state(project)
        raw,ledger=_json(project,base.SCOPE_PATHS['console']['ledger'])
        task_raw=read(project,'workspace/owner_documents/state/dynamic_tasks.json')
        previous=validate(project,ledger)
        refs=ledger.get('console_continuation_chain',[ledger.get('console_continuation_ref')])
        require(raw==canonical(ledger) and ledger==before and digest(raw)==proposal['before_ledger_ref']['sha256']
            and digest(task_raw)==proposal['before_task_state_ref']['sha256'] and json.loads(task_raw)==tasks
            and refs==proposal['previous_receipt_refs']
            and state['active_attempt_id']==proposal['selected_attempt_id']
            and proposal['selected_attempt_id'] not in previous['acknowledged_remote_unknown_attempt_ids']
            and state['source_identity_sha256']==source_identity_sha256,
            'console_continuation_current_ledger_changed')
        row=next(row for row in before['attempts'] if row['attempt_id']==proposal['selected_attempt_id'])
        receipt=dict(schema=TYPED_RECEIPT_VERSION,proposal_ref=prop_ref,review_ref=review_ref,
            previous_receipt_refs=refs,selected_attempt_id=row['attempt_id'],response_id=result['response_id'],
            context_sha256=row['context_sha256'],body_sha256=row['telemetry']['wire_body_sha256'],
            before_ledger_sha256=digest(raw),before_ledger_canonical_sha256=before['ledger_sha256'],
            historical_prefix_sha256=digest(before['attempts']),source_identity_sha256=source_identity_sha256,
            auth_source_identity_sha256=auth_source_identity_sha256,owner_operation_id=owner_operation_id,
            run_id=run_id,recorded_at=int(time.time()),local_http_closed=True,local_watchdog_finished=True,
            remote_outcome='UNKNOWN',usage='UNKNOWN',automatic_retry=False,server_cancellation_observed=False,
            operation_allowance_sha256=digest(proposal['operation_allowance']))
        receipt['receipt_sha256']=digest(receipt);receipt_raw=canonical(receipt)
        reference=dict(path=proposal['receipt_path'],sha256=digest(receipt_raw))
        ledger.update(version=CHAIN_VERSION,active_attempt_id=None,console_continuation_chain=refs+[reference])
        ledger['ledger_sha256']=digest({key:item for key,item in ledger.items() if key!='ledger_sha256'})
        pending=ledger_path.with_suffix('.pending')
        require(not pending.exists() and not pending.is_symlink(),'console_continuation_pending_write')
        fd=os.open(receipt_path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as stream:stream.write(receipt_raw);stream.flush();os.fsync(stream.fileno())
        _sync_directory(receipt_path.parent)
        require(read(project,proposal['receipt_path'])==receipt_raw,'console_continuation_receipt_readback')
        _settings,settings=task_budget.read_json(project,task_budget.SETTINGS)
        _record,record=task_budget.read_json(project,task_budget.TRANSITION)
        task_budget.validate_ledger(project,ledger,record,settings)
        fd=os.open(pending,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as stream:stream.write(canonical(ledger));stream.flush();os.fsync(stream.fileno())
        os.replace(pending,ledger_path);_sync_directory(ledger_path.parent)
        after=task_budget.read_state(project)
        require(after['counted']==len(before['attempts']) and after['active_attempt_id'] is None
            and read(project,base.SCOPE_PATHS['console']['ledger'])==canonical(ledger),
            'console_continuation_ledger_readback')
        return dict(receipt_ref=reference,proposal_ref=prop_ref,owner_operation_id=owner_operation_id,
            run_id=run_id,counted=len(before['attempts']),local_occupancy_released=True,server_outcome='UNKNOWN',
            new_request_started=False)


def typed_predecessor(project,proposal_ref,prior=None):
    """Verify the unchanged selected predecessor without acknowledging occupancy."""
    from review.transport import model_scope as base
    prop_ref,_review_ref,proposal,before,tasks,result,review=typed_approval(project,proposal_ref,current=True)
    raw=read(project,base.SCOPE_PATHS['console']['ledger'])
    task_raw=read(project,'workspace/owner_documents/state/dynamic_tasks.json')
    require(raw==canonical(before) and digest(raw)==proposal['before_ledger_ref']['sha256']
        and task_raw==canonical(tasks) and digest(task_raw)==proposal['before_task_state_ref']['sha256']
        and tasks.get('active_task_id') is None,
        'console_continuation_typed_predecessor_changed')
    checked=validate(project,before)
    require(proposal['selected_attempt_id'] not in checked['acknowledged_remote_unknown_attempt_ids'],
        'console_continuation_typed_selected_already_acknowledged')
    path=Path(project)/proposal['receipt_path']
    require(not path.exists() and not path.is_symlink(), 'console_continuation_already_applied_or_incomplete')
    selected=next(row for row in before['attempts'] if row['attempt_id']==proposal['selected_attempt_id'])
    if prior is not None:
        require(type(prior)is dict and prior.get('operation_id')==selected['owner_operation_id']
            and prior.get('console_run_id')==selected['run_id'], 'console_continuation_typed_owner_predecessor')
    ids=proposal['operation_allowance']['task_ids']
    first=proposal['operation_allowance']['actions'][0]['task_id']
    require(first==selected['round_binding']['task_id'],'console_continuation_typed_task_predecessor')
    require(tasks['tasks'][first]['status']=='FAILED'
        and all(tasks['tasks'][tid]['status'] in ('FAILED','QUEUED','COMPLETED') for tid in ids.values()),
        'console_continuation_typed_task_predecessor')
    return dict(proposal_ref=prop_ref,task_ids=dict(ids),before_task_state_ref=proposal['before_task_state_ref'],
        selected_attempt_id=proposal['selected_attempt_id'],counted=len(before['attempts']),
        old_owner_operation_id=selected['owner_operation_id'],old_run_id=selected['run_id'],
        source_identity_sha256=review['source_identity_sha256'],
        auth_source_identity_sha256=review['auth_source_identity_sha256'])


ROUND_FIELDS=frozenset({'task_id','round_id','profile','task_spec_sha256','dependencies_sha256','max_attempts'})
PROOF_FIELDS=frozenset({'schema','receipt_ref','proposal_ref','owner_operation_id','run_id','action_index',
    'action_id','mode','lifetime_round'})
RELATIVE_PROOF_FIELDS=PROOF_FIELDS|{'allowance_sha256','task_spec_sha256','before_round_count',
    'before_history_sha256','predecessor_result_ref','memory_result_ref'}


def validate_round_binding(value):
    """Validate the finite data shape; allowance authority is checked separately."""
    require(type(value)is dict and set(value) in (ROUND_FIELDS,ROUND_FIELDS|{'operation_allowance'},ROUND_FIELDS|{'normal_round_scope'})
        and type(value['task_id'])is str and re.fullmatch('radik-task:[0-9a-f]{32}',value['task_id'])
        and type(value['round_id'])is str and re.fullmatch('task-round:[0-9a-f]{32}',value['round_id'])
        and value['profile'] in ('compare','explain','verify')
        and all(type(value[key])is str and re.fullmatch('[0-9a-f]{64}',value[key])
            for key in ('task_spec_sha256','dependencies_sha256'))
        and type(value['max_attempts'])is int and value['max_attempts'] in (0,3), 'task_scope_round_binding')
    proof=value.get('operation_allowance')
    if 'normal_round_scope' in value:
        from .normal_session import validate_round_shape
        validate_round_shape(value)
    elif proof is None:
        require(value['max_attempts']==3,'console_allowance_memory_requires_proof')
    else:
        relative=type(proof)is dict and proof.get('schema')==RELATIVE_ROUND_ALLOWANCE_VERSION
        require(type(proof)is dict and set(proof)==(RELATIVE_PROOF_FIELDS if relative else PROOF_FIELDS)
            and proof['schema'] in (ROUND_ALLOWANCE_VERSION,RELATIVE_ROUND_ALLOWANCE_VERSION)
            and type(proof['owner_operation_id'])is str and re.fullmatch('[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',proof['owner_operation_id'])
            and type(proof['run_id'])is str and re.fullmatch('[0-9a-f]{12}',proof['run_id'])
            and type(proof['action_index'])is int and 0<=proof['action_index']<4
            and proof['action_id'] in ACTION_IDS and proof['mode'] in ('COLD','MEMORY_ONLY')
            and type(proof['lifetime_round'])is int and proof['lifetime_round']>=1
            and (relative or proof['lifetime_round']<=64)
            and value['max_attempts']==(0 if proof['mode']=='MEMORY_ONLY' else 3),
            'console_allowance_round_shape')
        if relative:
            require(all(type(proof[key])is str and re.fullmatch('[0-9a-f]{64}',proof[key]) for key in
                ('allowance_sha256','task_spec_sha256','before_history_sha256'))
                and proof['task_spec_sha256']==value['task_spec_sha256']
                and type(proof['before_round_count'])is int and proof['before_round_count']>=0,
                'console_relative_round_shape')
            for key in ('predecessor_result_ref','memory_result_ref'):
                if proof[key] is not None:_result_ref_shape(proof[key])
        _ref(proof['receipt_ref'],receipt=True);_ref(proof['proposal_ref'])
    return value


def _result_ref_shape(value):
    require(type(value)is dict and set(value)=={'task_id','filename','sha256','result_id','accepted_at','valid_to'}
        and type(value['task_id'])is str and re.fullmatch('radik-task:[0-9a-f]{32}',value['task_id'])
        and type(value['sha256'])is str and re.fullmatch('[0-9a-f]{64}',value['sha256'])
        and value['filename']==value['task_id'].split(':')[-1]+'-'+value['sha256']+'.json'
        and type(value['result_id'])is str and re.fullmatch('radik:dynamic_result:[0-9a-f]{64}',value['result_id'])
        and type(value['accepted_at'])is int and type(value['valid_to'])is int
        and 0<=value['accepted_at']<value['valid_to'],'console_relative_result_reference')
    return value


def _round_result(project,state,entry,before_sequence):
    """Bind a completed predecessor to its exact retained result bytes."""
    _sequence,binding,started,_lifetime=entry;row=state['tasks'][binding['task_id']]
    between=[event for event in row['history'] if started['sequence']<event['sequence']<before_sequence]
    accepted=[event for event in between if event['kind']=='ROUND_ACCEPTED']
    require(len(accepted)==1 and not any(event['kind'] in ('ROUND_STOPPED_WITHOUT_RETRY',
        'ACCEPTED_RESULT_RETAINED_WITH_LATE_FAILURE','PROCESS_RESTART_INTERRUPTED','ROUND_STARTED') for event in between),
        'console_relative_predecessor_not_accepted')
    result_events=[event for event in row['history'] if event['kind'] in
        ('ROUND_ACCEPTED','ACCEPTED_RESULT_RETAINED_WITH_LATE_FAILURE')]
    require(len(result_events)==len(row['results']),'console_relative_result_history')
    index=next(index for index,event in enumerate(result_events) if event['sequence']==accepted[0]['sequence'])
    reference=dict(task_id=binding['task_id'],**row['results'][index]);_result_ref_shape(reference)
    raw=read(project,'workspace/owner_documents/output/'+reference['filename'],cap=262144)
    result=json.loads(raw)
    require(digest(raw)==reference['sha256'] and all(result.get(key)==reference[key] for key in
        ('task_id','result_id','accepted_at','valid_to')) and result.get('version')=='radik.dynamic.result.v01',
        'console_relative_result_readback')
    return reference


def _relative_round_proof(project,state,authority,entries,index,before_sequence):
    allowance=authority['proposal']['operation_allowance'];action=allowance['actions'][index]
    receipt=authority['receipt']
    predecessor=None if index==0 else _round_result(project,state,entries[index-1],before_sequence)
    memory=None
    if action['mode']=='MEMORY_ONLY':
        candidates=[entry for entry in entries[:index] if entry[1]['operation_allowance']['action_id']==action['memory_result_action_id']]
        require(len(candidates)==1,'console_relative_allowance_memory_predecessor')
        memory=_round_result(project,state,candidates[0],before_sequence)
        require(memory['task_id']==action['task_id'],'console_relative_allowance_memory_predecessor')
    return dict(schema=RELATIVE_ROUND_ALLOWANCE_VERSION,receipt_ref=authority['receipt_ref'],
        proposal_ref=authority['proposal_ref'],owner_operation_id=receipt['owner_operation_id'],run_id=receipt['run_id'],
        action_index=index,action_id=action['action_id'],mode=action['mode'],lifetime_round=action['lifetime_round'],
        allowance_sha256=digest(allowance),task_spec_sha256=action['task_spec_sha256'],
        before_round_count=action['before_round_count'],before_history_sha256=action['before_history_sha256'],
        predecessor_result_ref=predecessor,memory_result_ref=memory)


def _task_state(project):
    raw,value=_json(project,'workspace/owner_documents/state/dynamic_tasks.json')
    require(raw==canonical(value) and type(value.get('tasks'))is dict and len(value['tasks'])<=64,
        'console_allowance_task_state')
    return value


def _authorities(project,ledger):
    if ledger.get('version')=='radik.console_turn_ledger.v05':
        from .normal_session import historical_ledger
        ledger=historical_ledger(project,ledger)
    if ledger.get('version')!=CHAIN_VERSION:return []
    validate(project,ledger)
    result=[]
    for ref in ledger['console_continuation_chain'][1:]:
        _raw,receipt=_ref_json(project,ref,receipt=True)
        proposal_ref,_review,proposal,before,tasks,_result,_seal=typed_approval(project,
            receipt['proposal_ref'],receipt['review_ref'])
        result.append(dict(receipt_ref=ref,receipt=receipt,proposal_ref=proposal_ref,proposal=proposal,
            before=before,tasks=tasks))
    return result


def validate_allowance_history(project,ledger,task_state=None):
    """Reconcile durable task slots and counted rows, with no state construction."""
    authorities=_authorities(project,ledger)
    if not authorities:return {}
    state=_task_state(project) if task_state is None else task_state
    from .normal_session import validate_history
    validate_history(project,ledger,state)
    rounds={};sequences=[]
    for tid,row in state['tasks'].items():
        require(type(row.get('history'))is list and len(row['history'])<=256,'console_allowance_task_state')
        lifetime=0
        for event in row['history']:
            if event.get('kind')!='ROUND_STARTED':continue
            lifetime+=1
            binding=event.get('operation_round')
            if binding is None:
                require(lifetime<=BASE_ROUND_LIMIT,'task_round_budget_exhausted')
                continue
            validate_round_binding(binding)
            require(set(event)=={'sequence','at','kind','operation_round'}
                and type(event['sequence'])is int and type(event['at'])is int
                and event['sequence']>0 and event['at']>=0, 'console_allowance_round_history_binding')
            require(binding['task_id']==tid and binding['round_id'] not in rounds,
                'console_allowance_round_history_binding')
            rounds[binding['round_id']]=(binding,event,lifetime)
            proof=binding.get('operation_allowance')
            require(proof is not None or 'normal_round_scope' in binding
                or lifetime<=BASE_ROUND_LIMIT,'task_round_budget_exhausted')
    for authority in authorities:
        proposal=authority['proposal'];before_tasks=authority['tasks'];receipt=authority['receipt']
        entries=[]
        for tid in proposal['operation_allowance']['task_ids'].values():
            require(tid in state['tasks'] and all(state['sources'].get(key)==value
                    for key,value in before_tasks['sources'].items())
                and all(state['tasks'][tid][key]==before_tasks['tasks'][tid][key]
                    for key in ('spec','draft','spec_history'))
                and state['tasks'][tid]['history'][:len(before_tasks['tasks'][tid]['history'])]
                    ==before_tasks['tasks'][tid]['history'], 'console_allowance_task_origin_changed')
        for rid,(binding,event,lifetime) in rounds.items():
            proof=binding.get('operation_allowance')
            if proof is None or proof['receipt_ref']!=authority['receipt_ref']:continue
            require(proof['proposal_ref']==authority['proposal_ref']
                and proof['owner_operation_id']==receipt['owner_operation_id']
                and proof['run_id']==receipt['run_id'] and proof['lifetime_round']==lifetime,
                'console_allowance_round_history_binding')
            entries.append((event['sequence'],binding,event,lifetime))
        entries.sort(key=lambda item:item[0])
        require(len(entries)<=len(proposal['operation_allowance']['actions']), 'console_allowance_exhausted')
        for index,(_seq,binding,event,lifetime) in enumerate(entries):
            action=proposal['operation_allowance']['actions'][index];proof=binding['operation_allowance']
            relative=proposal['operation_allowance']['schema']==RELATIVE_ALLOWANCE_VERSION
            require(proof['schema']==(RELATIVE_ROUND_ALLOWANCE_VERSION if relative else ROUND_ALLOWANCE_VERSION),
                'console_relative_allowance_version_binding')
            if relative:
                require(proof==_relative_round_proof(project,state,authority,entries,index,event['sequence']),
                    'console_relative_round_binding')
            require(proof['action_index']==index and proof['action_id']==action['action_id']
                and proof['mode']==action['mode'] and binding['task_id']==action['task_id']
                and lifetime==action['lifetime_round'] and binding['max_attempts']==action['max_provider_attempts']
                and binding['task_spec_sha256']==digest(state['tasks'][binding['task_id']]['spec']),
                'console_allowance_action_binding')
            if index:
                previous_binding=entries[index-1][1];previous_event=entries[index-1][2]
                history=state['tasks'][previous_binding['task_id']]['history']
                between=[item for item in history if previous_event['sequence']<item['sequence']<event['sequence']]
                require(any(item['kind']=='ROUND_ACCEPTED' for item in between)
                    and not any(item['kind'] in ('ROUND_STOPPED_WITHOUT_RETRY','ACCEPTED_RESULT_RETAINED_WITH_LATE_FAILURE',
                        'PROCESS_RESTART_INTERRUPTED') for item in between), 'console_allowance_previous_action_not_accepted')
        authority['entries']=entries
        sequences.append(authority)
    refs={item['receipt_ref']['path']:item for item in authorities}
    for binding,event,lifetime in rounds.values():
        proof=binding.get('operation_allowance')
        if proof is not None:
            require(proof['receipt_ref']['path'] in refs
                and proof['receipt_ref']==refs[proof['receipt_ref']['path']]['receipt_ref'],
                'console_allowance_unknown_receipt')
    for row in ledger['attempts'][3:]:
        binding=row['round_binding'];proof=binding.get('operation_allowance')
        for authority in authorities:
            receipt=authority['receipt']
            if row['owner_operation_id']==receipt['owner_operation_id'] and row['run_id']==receipt['run_id']:
                require(proof is not None and proof['receipt_ref']==authority['receipt_ref'],
                    'console_allowance_request_requires_slot')
        if proof is not None:
            require(binding['round_id'] in rounds and rounds[binding['round_id']][0]==binding
                and row['owner_operation_id']==proof['owner_operation_id'] and row['run_id']==proof['run_id']
                and binding['max_attempts']==3, 'console_allowance_request_history_binding')
    return dict(authorities=sequences,rounds=rounds)


def prepare_round(project,ledger,binding,*,owner_operation_id,run_id,operation_action=None,task_state=None):
    """Select exactly one next slot; TaskStore persists it before any reservation."""
    state=_task_state(project) if task_state is None else task_state
    checked=validate_allowance_history(project,ledger,state)
    lifetime=sum(event['kind']=='ROUND_STARTED' for event in state['tasks'][binding['task_id']]['history'])+1
    current=next((item for item in checked.get('authorities',[]) if
        item['receipt']['owner_operation_id']==owner_operation_id and item['receipt']['run_id']==run_id),None)
    candidate={key:item for key,item in binding.items() if key!='operation_allowance'}
    if current is None:
        require(operation_action is None and lifetime<=BASE_ROUND_LIMIT,'task_round_budget_exhausted')
        validate_round_binding(candidate)
        return candidate
    actions=current['proposal']['operation_allowance']['actions'];index=len(current['entries'])
    require(index<len(actions),'console_allowance_exhausted')
    action=actions[index]
    require(operation_action==action['action_id'] and candidate['task_id']==action['task_id']
        and lifetime==action['lifetime_round'] and candidate['max_attempts']==action['max_provider_attempts'],
        'console_allowance_next_action')
    if index:
        previous=current['entries'][-1]
        history=state['tasks'][previous[1]['task_id']]['history']
        later=[event for event in history if event['sequence']>previous[2]['sequence']]
        require(any(event['kind']=='ROUND_ACCEPTED' for event in later)
            and not any(event['kind'] in ('ROUND_STOPPED_WITHOUT_RETRY','ACCEPTED_RESULT_RETAINED_WITH_LATE_FAILURE',
                'PROCESS_RESTART_INTERRUPTED') for event in later), 'console_allowance_previous_action_not_accepted')
    if current['proposal']['operation_allowance']['schema']==RELATIVE_ALLOWANCE_VERSION:
        candidate['operation_allowance']=_relative_round_proof(project,state,current,current['entries'],index,state['sequence']+1)
    else:
        candidate['operation_allowance']=dict(schema=ROUND_ALLOWANCE_VERSION,receipt_ref=current['receipt_ref'],
            proposal_ref=current['proposal_ref'],owner_operation_id=owner_operation_id,run_id=run_id,
            action_index=index,action_id=action['action_id'],mode=action['mode'],lifetime_round=lifetime)
    validate_round_binding(candidate)
    require(binding['round_id'] not in checked['rounds'],'console_allowance_round_replay')
    return candidate


# Stage05 has a distinct fresh-task allowance; legacy ABC validators stay intact.
_validate_before_stage05_disposition = validate


def validate(project, ledger):
    previous = _validate_before_stage05_disposition(project, ledger)
    from .stage05_disposition import extend_status
    previous = extend_status(project, ledger, previous)
    from .stage05_disposition_successor import extend_status as extend_successor_status
    return extend_successor_status(project, ledger, previous)
