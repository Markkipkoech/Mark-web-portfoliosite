"""Strict RFC 8785 canonicalization and deterministic candidate identity."""

import hashlib
import json
import math
import re
from decimal import Decimal, DecimalException
from typing import Any, Iterable, NamedTuple


class CandidateIdentityError(ValueError):
    """Candidate input cannot be safely interpreted as RFC 8785 JSON."""


class CandidateIdentity(NamedTuple):
    raw_sha256: str
    canonical_sha256: str
    submission_id: str


_HEX_DIGEST = re.compile(r"^[0-9a-f]{64}$")
IDENTITY_CONTRACT_VERSION = "1"


def _unicode_scalar_string(value: str) -> str:
    """Combine escaped UTF-16 surrogate pairs and reject lone surrogates."""
    result = []
    index = 0
    while index < len(value):
        codepoint = ord(value[index])
        if 0xD800 <= codepoint <= 0xDBFF:
            if index + 1 >= len(value):
                raise CandidateIdentityError("JSON strings must contain valid Unicode")
            low = ord(value[index + 1])
            if not 0xDC00 <= low <= 0xDFFF:
                raise CandidateIdentityError("JSON strings must contain valid Unicode")
            result.append(chr(0x10000 + ((codepoint - 0xD800) << 10) + low - 0xDC00))
            index += 2
            continue
        if 0xDC00 <= codepoint <= 0xDFFF:
            raise CandidateIdentityError("JSON strings must contain valid Unicode")
        result.append(value[index])
        index += 1
    return "".join(result)


def _object_without_duplicate_keys(pairs: Iterable[Any]) -> dict:
    result = {}
    for raw_key, value in pairs:
        key = _unicode_scalar_string(raw_key)
        if key in result:
            raise CandidateIdentityError(
                "duplicate JSON object key {!r}".format(key)
            )
        result[key] = value
    return result


def _reject_nonstandard_constant(value: str) -> Any:
    raise CandidateIdentityError(
        "non-standard JSON constant {!r} is not permitted".format(value)
    )


def _parse_json_int(value: str) -> int:
    """Parse an integer using Python's standard configured digit limit."""
    try:
        return int(value)
    except ValueError as error:
        raise CandidateIdentityError(
            "JSON integer exceeds Python's configured digit limit"
        ) from error


def _parse_json_float(value: str) -> float:
    """Parse a JSON decimal into binary64 without accepting total underflow."""
    try:
        exact_value = Decimal(value)
        number = float(value)
    except (DecimalException, OverflowError, ValueError) as error:
        raise CandidateIdentityError(
            "JSON number cannot be represented as IEEE-754 binary64"
        ) from error

    if not math.isfinite(number):
        raise CandidateIdentityError("JSON number overflows IEEE-754 binary64")
    if exact_value != 0 and number == 0:
        raise CandidateIdentityError("nonzero JSON number underflows to zero")
    return number


def _normalize_parsed_strings(value: Any) -> Any:
    if isinstance(value, str):
        return _unicode_scalar_string(value)
    if isinstance(value, list):
        return [_normalize_parsed_strings(item) for item in value]
    if isinstance(value, dict):
        return {
            key: _normalize_parsed_strings(item) for key, item in value.items()
        }
    return value


def parse_candidate_json(raw_candidate: bytes) -> Any:
    """Decode UTF-8 JSON while rejecting ambiguous and non-I-JSON inputs."""
    if not isinstance(raw_candidate, bytes):
        raise TypeError("raw_candidate must be bytes")
    try:
        text = raw_candidate.decode("utf-8")
    except UnicodeDecodeError as error:
        raise CandidateIdentityError(
            "candidate is not valid UTF-8 at byte {}".format(error.start)
        ) from error

    try:
        parsed = json.loads(
            text,
            object_pairs_hook=_object_without_duplicate_keys,
            parse_constant=_reject_nonstandard_constant,
            parse_int=_parse_json_int,
            parse_float=_parse_json_float,
        )
    except CandidateIdentityError:
        raise
    except json.JSONDecodeError as error:
        raise CandidateIdentityError(
            "candidate contains malformed JSON at line {}, column {}: {}".format(
                error.lineno, error.colno, error.msg
            )
        ) from error
    except RecursionError as error:
        raise CandidateIdentityError("candidate JSON nesting is too deep") from error

    try:
        return _normalize_parsed_strings(parsed)
    except CandidateIdentityError:
        raise
    except RecursionError as error:
        raise CandidateIdentityError("candidate JSON nesting is too deep") from error


def _serialize_string(value: str) -> str:
    value = _unicode_scalar_string(value)
    pieces = ['"']
    escapes = {
        '"': '\\"',
        "\\": "\\\\",
        "\b": "\\b",
        "\t": "\\t",
        "\n": "\\n",
        "\f": "\\f",
        "\r": "\\r",
    }
    for character in value:
        codepoint = ord(character)
        if character in escapes:
            pieces.append(escapes[character])
        elif codepoint <= 0x1F:
            pieces.append("\\u{:04x}".format(codepoint))
        else:
            pieces.append(character)
    pieces.append('"')
    return "".join(pieces)


def _number_to_ecmascript(value: Any) -> str:
    # JCS numbers use IEEE-754 binary64 and ECMAScript's shortest round-trip form.
    if isinstance(value, bool):
        raise CandidateIdentityError("boolean values are not numbers here")
    if isinstance(value, int):
        try:
            number = float(value)
        except OverflowError as error:
            raise CandidateIdentityError(
                "integer cannot be represented as an IEEE-754 number"
            ) from error
        if not math.isfinite(number):
            raise CandidateIdentityError(
                "integer cannot be represented as an IEEE-754 number"
            )
        if int(number) != value:
            raise CandidateIdentityError(
                "integer changes value when represented as IEEE-754 binary64"
            )
    elif isinstance(value, float):
        number = value
    else:
        raise CandidateIdentityError("unsupported JSON number representation")

    if not math.isfinite(number):
        raise CandidateIdentityError("NaN and Infinity are not permitted")
    if number == 0:
        return "0"

    negative = number < 0
    shortest = repr(abs(number)).lower()
    if "e" in shortest:
        mantissa, exponent_text = shortest.split("e", 1)
        exponent = int(exponent_text)
    else:
        mantissa = shortest
        exponent = 0

    integer_part, _, fractional_part = mantissa.partition(".")
    digits = integer_part + fractional_part
    decimal_position = len(integer_part) + exponent
    leading_zeroes = len(digits) - len(digits.lstrip("0"))
    digits = digits.lstrip("0")
    decimal_position -= leading_zeroes
    digits = digits.rstrip("0") or "0"
    digit_count = len(digits)

    if digit_count <= decimal_position <= 21:
        result = digits + ("0" * (decimal_position - digit_count))
    elif 0 < decimal_position <= 21:
        result = digits[:decimal_position] + "." + digits[decimal_position:]
    elif -6 < decimal_position <= 0:
        result = "0." + ("0" * -decimal_position) + digits
    else:
        exponent = decimal_position - 1
        coefficient = digits[0]
        if digit_count > 1:
            coefficient += "." + digits[1:]
        result = coefficient + "e" + ("+" if exponent >= 0 else "") + str(exponent)

    return ("-" if negative else "") + result


def _utf16_sort_key(value: str) -> bytes:
    try:
        return value.encode("utf-16-be")
    except UnicodeEncodeError as error:
        raise CandidateIdentityError("object keys must contain valid Unicode") from error


def _canonicalize_value(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return _serialize_string(value)
    if isinstance(value, (int, float)):
        return _number_to_ecmascript(value)
    if isinstance(value, list):
        return "[" + ",".join(_canonicalize_value(item) for item in value) + "]"
    if isinstance(value, dict):
        if not all(isinstance(key, str) for key in value):
            raise CandidateIdentityError("JSON object keys must be strings")
        entries = []
        for key in sorted(value, key=_utf16_sort_key):
            entries.append(
                _serialize_string(key) + ":" + _canonicalize_value(value[key])
            )
        return "{" + ",".join(entries) + "}"
    raise CandidateIdentityError(
        "unsupported value type for RFC 8785: {}".format(type(value).__name__)
    )


def canonicalize_json(value: Any) -> bytes:
    """Return RFC 8785 canonical JSON encoded as UTF-8 bytes."""
    try:
        return _canonicalize_value(value).encode("utf-8")
    except CandidateIdentityError:
        raise
    except RecursionError as error:
        raise CandidateIdentityError("JSON value nesting is too deep") from error
    except UnicodeEncodeError as error:
        raise CandidateIdentityError("JSON strings must contain valid Unicode") from error


def derive_submission_id(
    contract_version: str,
    project_id: str,
    update_id: str,
    canonical_content_sha256: str,
) -> str:
    """Hash exactly the four approved identity inputs in canonical array form."""
    values = (contract_version, project_id, update_id)
    if any(not isinstance(value, str) or not value for value in values):
        raise CandidateIdentityError(
            "contract_version, project_id, and update_id must be non-empty strings"
        )
    if not isinstance(canonical_content_sha256, str) or not _HEX_DIGEST.fullmatch(
        canonical_content_sha256
    ):
        raise CandidateIdentityError(
            "canonical_content_sha256 must be a lowercase SHA-256 hex digest"
        )
    identity_bytes = canonicalize_json(
        [contract_version, project_id, update_id, canonical_content_sha256]
    )
    return "sha256:" + hashlib.sha256(identity_bytes).hexdigest()


def identify_candidate(raw_candidate: bytes) -> CandidateIdentity:
    """Calculate raw, canonical, and deterministic content-based identities."""
    candidate = parse_candidate_json(raw_candidate)
    if not isinstance(candidate, dict):
        raise CandidateIdentityError("candidate must be a JSON object")

    fields = ("schema_version", "project_id", "update_id")
    if any(not isinstance(candidate.get(field), str) or not candidate[field] for field in fields):
        raise CandidateIdentityError(
            "candidate requires non-empty schema_version, project_id, and update_id strings"
        )

    canonical_bytes = canonicalize_json(candidate)
    canonical_digest = hashlib.sha256(canonical_bytes).hexdigest()
    submission_id = derive_submission_id(
        IDENTITY_CONTRACT_VERSION,
        candidate["project_id"],
        candidate["update_id"],
        canonical_digest,
    )
    return CandidateIdentity(
        raw_sha256=hashlib.sha256(raw_candidate).hexdigest(),
        canonical_sha256=canonical_digest,
        submission_id=submission_id,
    )
