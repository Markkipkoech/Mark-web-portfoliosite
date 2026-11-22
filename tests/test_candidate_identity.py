import hashlib
import struct
import sys
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT / "portfolio-data" / "scripts"))

from candidate_identity import (  # noqa: E402
    CandidateIdentityError,
    IDENTITY_CONTRACT_VERSION,
    canonicalize_json,
    derive_submission_id,
    identify_candidate,
    parse_candidate_json,
)


class CandidateIdentityTests(unittest.TestCase):
    def test_rfc_8785_section_3_2_2_canonicalization_vector(self):
        raw = br'''{
          "numbers": [333333333.33333329, 1E30, 4.50, 2e-3,
                      0.000000000000000000000000001],
          "string": "\u20ac$\u000f\u000aA'\u0042\u0022\u005c\\\"\/",
          "literals": [null, true, false]
        }'''
        parsed = parse_candidate_json(raw)
        expected = (
            r'''{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],'''
            r'''"string":"€$\u000f\nA'B\"\\\\\"/"}'''
        ).encode("utf-8")
        self.assertEqual(canonicalize_json(parsed), expected)

    def test_rfc_8785_utf16_property_ordering_vector(self):
        value = {
            "€": "Euro Sign",
            "\r": "Carriage Return",
            "דּ": "Hebrew Letter Dalet With Dagesh",
            "1": "One",
            "😀": "Emoji: Grinning Face",
            "\u0080": "Control",
            "ö": "Latin Small Letter O With Diaeresis",
        }
        expected = (
            r'''{"\r":"Carriage Return","1":"One","":"Control",'''
            r'''"ö":"Latin Small Letter O With Diaeresis","€":"Euro Sign",'''
            r'''"😀":"Emoji: Grinning Face","דּ":"Hebrew Letter Dalet With Dagesh"}'''
        ).encode("utf-8")
        self.assertEqual(canonicalize_json(value), expected)

    def test_rfc_8785_appendix_b_number_serialization_vectors(self):
        vectors = {
            "0000000000000000": "0",
            "8000000000000000": "0",
            "0000000000000001": "5e-324",
            "8000000000000001": "-5e-324",
            "7fefffffffffffff": "1.7976931348623157e+308",
            "ffefffffffffffff": "-1.7976931348623157e+308",
            "4340000000000000": "9007199254740992",
            "c340000000000000": "-9007199254740992",
            "4430000000000000": "295147905179352830000",
            "44b52d02c7e14af5": "9.999999999999997e+22",
            "44b52d02c7e14af6": "1e+23",
            "44b52d02c7e14af7": "1.0000000000000001e+23",
            "444b1ae4d6e2ef4e": "999999999999999700000",
            "444b1ae4d6e2ef4f": "999999999999999900000",
            "444b1ae4d6e2ef50": "1e+21",
            "3eb0c6f7a0b5ed8c": "9.999999999999997e-7",
            "3eb0c6f7a0b5ed8d": "0.000001",
            "41b3de4355555553": "333333333.3333332",
            "41b3de4355555554": "333333333.33333325",
            "41b3de4355555555": "333333333.3333333",
            "41b3de4355555556": "333333333.3333334",
            "41b3de4355555557": "333333333.33333343",
            "becbf647612f3696": "-0.0000033333333333333333",
            "43143ff3c1cb0959": "1424953923781206.2",
        }
        for binary64_hex, expected in vectors.items():
            with self.subTest(binary64=binary64_hex):
                number = struct.unpack(">d", bytes.fromhex(binary64_hex))[0]
                self.assertEqual(canonicalize_json(number), expected.encode("ascii"))

    def test_object_keys_sort_recursively_and_arrays_keep_order(self):
        value = {"z": [{"b": 2, "a": 1}], "a": [3, 2]}
        self.assertEqual(canonicalize_json(value), b'{"a":[3,2],"z":[{"a":1,"b":2}]}')

    def test_string_escaping_uses_jcs_rules(self):
        value = '"\\\b\t\n\f\r\x00\x1f/é'
        expected = b'"\\\"\\\\\\b\\t\\n\\f\\r\\u0000\\u001f/\xc3\xa9"'
        self.assertEqual(canonicalize_json(value), expected)

    def test_escaped_surrogate_pairs_become_unicode_scalar_values(self):
        self.assertEqual(parse_candidate_json(b'"\\ud83d\\ude00"'), "😀")
        self.assertEqual(canonicalize_json("😀"), '"😀"'.encode("utf-8"))

    def test_duplicate_keys_are_rejected_including_equivalent_unicode_keys(self):
        for raw in (
            b'{"key":1,"key":2}',
            b'{"nested":{"key":1,"key":2}}',
            b'{"\\ud83d\\ude00":1,"\xf0\x9f\x98\x80":2}',
        ):
            with self.subTest(raw=raw), self.assertRaises(CandidateIdentityError):
                parse_candidate_json(raw)

    def test_invalid_json_utf8_constants_and_unsupported_numbers_are_rejected(self):
        invalid_inputs = (
            b'{"a":',
            b'\xff',
            b'{"a":NaN}',
            b'{"a":Infinity}',
            b'{"a":-Infinity}',
            b'"\\ud800"',
            b'"\\udc00"',
        )
        for raw in invalid_inputs:
            with self.subTest(raw=raw), self.assertRaises(CandidateIdentityError):
                parse_candidate_json(raw)

        with self.assertRaisesRegex(CandidateIdentityError, "overflows"):
            parse_candidate_json(b'{"a":1e400}')

    def test_integer_over_runtime_digit_limit_raises_candidate_identity_error(self):
        if not hasattr(sys, "get_int_max_str_digits"):
            self.skipTest("interpreter does not expose an integer digit limit")

        digit_limit = sys.get_int_max_str_digits()
        if digit_limit == 0:
            self.skipTest("interpreter integer digit limit is disabled")

        oversized_integer = b"1" * (digit_limit + 1)
        with self.assertRaisesRegex(
            CandidateIdentityError, "configured digit limit"
        ):
            parse_candidate_json(oversized_integer)

    def test_binary64_integer_boundaries_and_exact_large_integer(self):
        accepted = (
            (9007199254740991, b"9007199254740991"),
            (9007199254740992, b"9007199254740992"),
            (-9007199254740991, b"-9007199254740991"),
            (-9007199254740992, b"-9007199254740992"),
            (295147905179352825856, b"295147905179352830000"),
        )
        for integer, expected in accepted:
            with self.subTest(integer=integer):
                parsed = parse_candidate_json(str(integer).encode("ascii"))
                self.assertEqual(canonicalize_json(parsed), expected)

        for integer in (9007199254740993, -9007199254740993):
            with self.subTest(integer=integer):
                parsed = parse_candidate_json(str(integer).encode("ascii"))
                with self.assertRaisesRegex(CandidateIdentityError, "changes value"):
                    canonicalize_json(parsed)

    def test_decimal_underflow_is_rejected_but_binary64_subnormal_is_preserved(self):
        for token in (b"1e-400", b"-1e-400", b"1.25e-9999"):
            with self.subTest(token=token), self.assertRaisesRegex(
                CandidateIdentityError, "underflows to zero"
            ):
                parse_candidate_json(token)

        self.assertEqual(canonicalize_json(parse_candidate_json(b"5e-324")), b"5e-324")

    def test_all_zero_forms_canonicalize_to_zero(self):
        for token in (b"0", b"-0", b"0.0", b"-0.0"):
            with self.subTest(token=token):
                self.assertEqual(canonicalize_json(parse_candidate_json(token)), b"0")

    def test_decimal_and_exponent_integer_values_use_parsed_binary64(self):
        tokens = (
            (b"9007199254740992.0", b"9007199254740992"),
            (b"9007199254740993.0", b"9007199254740992"),
            (b"9007199254740993e0", b"9007199254740992"),
            (b"9007199254740994e0", b"9007199254740994"),
        )
        for token, expected in tokens:
            with self.subTest(token=token):
                self.assertEqual(
                    canonicalize_json(parse_candidate_json(token)), expected
                )

    def test_rfc_8785_decimal_rounding_example_is_preserved(self):
        parsed = parse_candidate_json(b"333333333.33333329")
        self.assertEqual(canonicalize_json(parsed), b"333333333.3333333")

    def test_raw_digest_changes_when_only_json_formatting_changes(self):
        compact = b'{"schema_version":"1.0","project_id":"companyhub","update_id":"first"}'
        spaced = b'{ "schema_version": "1.0", "project_id": "companyhub", "update_id": "first" }'
        compact_identity = identify_candidate(compact)
        spaced_identity = identify_candidate(spaced)
        self.assertNotEqual(compact_identity.raw_sha256, spaced_identity.raw_sha256)
        self.assertEqual(
            compact_identity.raw_sha256, hashlib.sha256(compact).hexdigest()
        )
        self.assertEqual(compact_identity.canonical_sha256, spaced_identity.canonical_sha256)
        self.assertEqual(
            compact_identity.canonical_sha256,
            hashlib.sha256(
                b'{"project_id":"companyhub","schema_version":"1.0","update_id":"first"}'
            ).hexdigest(),
        )
        self.assertEqual(compact_identity.submission_id, spaced_identity.submission_id)

    def test_content_change_changes_canonical_digest_and_submission_identity(self):
        first = b'{"schema_version":"1.0","project_id":"companyhub","update_id":"first","title":"A"}'
        revised = b'{"schema_version":"1.0","project_id":"companyhub","update_id":"first","title":"B"}'
        self.assertNotEqual(
            identify_candidate(first).canonical_sha256,
            identify_candidate(revised).canonical_sha256,
        )
        self.assertNotEqual(
            identify_candidate(first).submission_id,
            identify_candidate(revised).submission_id,
        )

    def test_submission_identity_is_deterministic_and_uses_exact_approved_inputs(self):
        base = ("1", "companyhub", "first", "a" * 64)
        expected = derive_submission_id(*base)
        independently_encoded_inputs = b'["1","companyhub","first","' + (
            b"a" * 64
        ) + b'"]'
        self.assertEqual(
            expected,
            "sha256:" + hashlib.sha256(independently_encoded_inputs).hexdigest(),
        )
        self.assertEqual(expected, derive_submission_id(*base))
        self.assertTrue(expected.startswith("sha256:"))

        for index in range(len(base)):
            changed = list(base)
            changed[index] = "b" * 64 if index == 3 else changed[index] + "-changed"
            with self.subTest(changed_input=index):
                self.assertNotEqual(expected, derive_submission_id(*changed))

    def test_source_commit_observation_is_not_an_identity_input(self):
        candidate_bytes = (
            b'{"schema_version":"1.0","project_id":"companyhub",'
            b'"update_id":"first"}'
        )
        candidate_identity = identify_candidate(candidate_bytes)
        inputs = (
            IDENTITY_CONTRACT_VERSION,
            "companyhub",
            "first",
            candidate_identity.canonical_sha256,
        )
        source_observations = (
            {"source_commit_sha": "1" * 40, "candidate_bytes": candidate_bytes},
            {"source_commit_sha": "2" * 40, "candidate_bytes": candidate_bytes},
        )
        identities = [
            identify_candidate(observation["candidate_bytes"]).submission_id
            for observation in source_observations
        ]
        self.assertEqual(identities[0], derive_submission_id(*inputs))
        self.assertEqual(identities[0], identities[1])

    def test_identity_contract_version_is_central_and_independent_of_schema_version(self):
        self.assertEqual(IDENTITY_CONTRACT_VERSION, "1")
        schema_v1 = (
            b'{"schema_version":"1.0","project_id":"companyhub",'
            b'"update_id":"first"}'
        )
        schema_v2 = (
            b'{"schema_version":"2.0","project_id":"companyhub",'
            b'"update_id":"first"}'
        )
        identity_v1 = identify_candidate(schema_v1)
        identity_v2 = identify_candidate(schema_v2)

        self.assertNotEqual(identity_v1.canonical_sha256, identity_v2.canonical_sha256)
        self.assertEqual(
            identity_v1.submission_id,
            derive_submission_id(
                IDENTITY_CONTRACT_VERSION,
                "companyhub",
                "first",
                identity_v1.canonical_sha256,
            ),
        )
        self.assertEqual(
            identity_v2.submission_id,
            derive_submission_id(
                IDENTITY_CONTRACT_VERSION,
                "companyhub",
                "first",
                identity_v2.canonical_sha256,
            ),
        )
        self.assertNotEqual(
            identity_v2.submission_id,
            derive_submission_id(
                "2.0", "companyhub", "first", identity_v2.canonical_sha256
            ),
        )

    def test_invalid_submission_identity_inputs_are_rejected(self):
        invalid_inputs = (
            ("", "companyhub", "first", "a" * 64),
            ("1.0", "", "first", "a" * 64),
            ("1.0", "companyhub", "", "a" * 64),
            ("1.0", "companyhub", "first", "A" * 64),
            ("1.0", "companyhub", "first", "not-a-digest"),
        )
        for args in invalid_inputs:
            with self.subTest(args=args), self.assertRaises(CandidateIdentityError):
                derive_submission_id(*args)

    def test_candidate_identity_requires_contract_fields(self):
        for raw in (
            b'[]',
            b'{"project_id":"companyhub","update_id":"first"}',
            b'{"schema_version":"1.0","project_id":"companyhub","update_id":1}',
        ):
            with self.subTest(raw=raw), self.assertRaises(CandidateIdentityError):
                identify_candidate(raw)


if __name__ == "__main__":
    unittest.main()
