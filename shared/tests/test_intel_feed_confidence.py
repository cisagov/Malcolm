"""Test expanded Zeek intel metadata with real feed indicator classes."""

import unittest

import mandiant_threatintel as mandiant
import zeek_threat_feed_utils as mapper
from stix2.v21 import Indicator


def stix_indicator(confidence=None):
    fields = {
        "name": "Indicator",
        "pattern_type": "stix",
        "pattern": "[domain-name:value = 'sample.example.com']",
        "valid_from": "2026-01-01T00:00:00Z",
        "created": "2026-01-01T00:00:00Z",
        "modified": "2026-01-02T00:00:00Z",
    }
    if confidence is not None:
        fields["confidence"] = confidence
    return Indicator(**fields)


def mandiant_indicator(score):
    return mandiant.FQDNIndicator(
        client=None,
        response={
            "id": "fqdn--sample",
            "type": "fqdn",
            "value": "sample.example.com",
            "mscore": score,
            "sources": [],
            "misp": {},
            "first_seen": "2026-01-01T00:00:00Z",
            "last_seen": "2026-01-02T00:00:00Z",
        },
    )


class IntelMetadataTests(unittest.TestCase):
    def test_mandiant_score_populated_for_valid_range(self):
        for score in (0, 35, 100):
            row = mapper.map_mandiant_indicator_to_zeek(mandiant_indicator(score))[0]
            self.assertNotIn(mapper.ZEEK_INTEL_META_THREAT_SCORE, row)
            self.assertEqual(row[mapper.ZEEK_INTEL_META_CONFIDENCE], str(score))
            self.assertEqual(
                row[mapper.ZEEK_INTEL_CIF_CONFIDENCE], str(round(score / 10))
            )

    def test_invalid_scores_are_not_emitted(self):
        for value in (-1, 101, "invalid"):
            row = mapper.map_mandiant_indicator_to_zeek(mandiant_indicator(value))[0]
            self.assertNotIn(mapper.ZEEK_INTEL_META_THREAT_SCORE, row)
            self.assertNotIn(mapper.ZEEK_INTEL_META_CONFIDENCE, row)
            self.assertNotIn(mapper.ZEEK_INTEL_CIF_CONFIDENCE, row)

    def test_stix_confidence_maps_only_when_present(self):
        for value in (0, 31, 72, 100):
            row = mapper.map_stix_indicator_to_zeek(stix_indicator(value))[0]
            self.assertEqual(row[mapper.ZEEK_INTEL_META_CONFIDENCE], str(value))
            self.assertEqual(
                row[mapper.ZEEK_INTEL_CIF_CONFIDENCE], str(round(value / 10))
            )
            self.assertNotIn(mapper.ZEEK_INTEL_META_THREAT_SCORE, row)

    def test_stix_without_confidence_does_not_invent_one(self):
        row = mapper.map_stix_indicator_to_zeek(stix_indicator())[0]
        self.assertNotIn(mapper.ZEEK_INTEL_META_CONFIDENCE, row)
        self.assertNotIn(mapper.ZEEK_INTEL_META_THREAT_SCORE, row)
